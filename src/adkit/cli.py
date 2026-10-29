"""adkit 命令行：build（抓取→解析→去重吸收→质量门→渲染）、explain（规则归因查询）。"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import tomllib

from . import fetch, merge, quality, render
from .ir import Rule, norm_domain, SUFFIX
from .parsers import PARSERS

ROOT = pathlib.Path(__file__).resolve().parents[2]
CFG = ROOT / "config"
DIST = ROOT / "dist"


def load_cfg():
    with open(CFG / "sources.toml", "rb") as f:
        cfg = tomllib.load(f)
    with open(CFG / "rewrite.toml", "rb") as f:
        rw = tomllib.load(f)
    return cfg, rw


def load_list(path: pathlib.Path):
    out = []
    for ln in path.read_text("utf-8").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
    return out


def build_rules(cfg, rw, live: bool, only_ids=None):
    texts = fetch.load_sources(cfg, ROOT / "cache", ROOT / "snapshots", live=live, only_ids=only_ids)
    all_rules, per, skipped, warns = [], {}, {}, []
    for sid, text, warn in texts:
        src = next(s for s in cfg["sources"] if s["id"] == sid)
        if text is None:
            per[sid] = 0
            warns.append(f"[{sid}] 源完全失败（无快照可用）: {warn}")
            continue
        if warn:
            warns.append(f"[{sid}] {warn}")
        rules, sk = PARSERS[src["parser"]](text, sid)
        all_rules.extend(rules)
        per[sid] = len(rules)
        skipped[sid] = sk
    merged = merge.dedup(all_rules)
    merged, absorbed = merge.absorb(merged)
    wl_rules = []
    for d in load_list(CFG / "whitelist.txt"):
        nd = norm_domain(d)
        if nd:
            wl_rules.append(Rule(SUFFIX, nd, "DIRECT", ["whitelist"]))
    return wl_rules + merged, per, skipped, absorbed, warns


def cmd_build(args):
    cfg, rw = load_cfg()
    rules, per, skipped, absorbed, warns = build_rules(cfg, rw, live=not args.offline, only_ids=args.only)
    for w in warns:
        print("警告:", w)
    total = sum(per.values())
    if total < 5000:
        print(f"错误：解析总量仅 {total} 条（远低于下限 5000），疑似上游集体异常，拒绝发布")
        return 2

    canaries = load_list(CFG / "canary.txt")
    bad = quality.canary_check([r for r in rules if r.is_reject()], canaries)
    if bad:
        print(f"错误：canary 金丝雀被 REJECT，共 {len(bad)} 处（金丝雀域名必须放行）：")
        for d, r in bad[:40]:
            print(f"  ✗ {d} 被规则 [{r.type},{r.pattern},{r.action}]（来源: {'+'.join(r.sources)}）拦截")
        if not args.ignore_canary:
            print("构建终止（keep-last-good：dist 分支保持上一版）。修复：加入 config/whitelist.txt 或禁用肇事源。")
            return 2
        print("--ignore-canary 指定，强行继续（不建议！）")

    prev_stats = None
    if (DIST / "stats.json").exists():
        prev_stats = json.loads((DIST / "stats.json").read_text("utf-8"))
        for w in quality.count_deviation(prev_stats, {"per_source": per}):
            print("警告:", w)

    rewrites = [w for w in rw.get("rewrite", []) if w.get("enabled", True)]
    mitm_hosts = [h.strip() for h in rw.get("mitm", {}).get("hosts", []) if h.strip()]
    built = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    src_names = " + ".join(s["id"] + "(" + s.get("license", "?") + ")" for s in cfg["sources"] if s.get("enabled", True))
    header = (
        "# ShadowRocketADBlock —— adkit 自动构建产物，请勿手改\n"
        "# 白名单: config/whitelist.txt | 开屏改写: config/rewrite.toml | 源开关: config/sources.toml\n"
        f"# 构建(UTC): {built} | adkit v0.1\n"
        f"# 源: {src_names}\n"
        "# 本文件不含任何 CA/私钥：[MITM] 仅 hostname 清单，HTTPS 解密使用你设备自己的证书"
    )

    outs = {
        "stable/adkit.conf": render.render_full_conf(rules, rewrites, mitm_hosts, cfg["meta"]["stable_url"], header),
        "latest/adkit.conf": render.render_full_conf(rules, rewrites, mitm_hosts, cfg["meta"]["latest_url"], header),
        "adkit-adonly.conf": render.render_adonly(rules, header),
    }
    for name, text in outs.items():
        quality.scrub_assert(text)

    DIST.mkdir(exist_ok=True)
    for name, text in outs.items():
        p = DIST / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, "utf-8")

    stats = {
        "built_utc": built,
        "per_source": per,
        "skipped_lines": skipped,
        "absorbed": absorbed,
        "total_rendered": len(rules),
        "whitelist": len(load_list(CFG / "whitelist.txt")),
        "rewrites": len(rewrites),
        "mitm_hosts": len(mitm_hosts),
        "canary": {"size": len(canaries), "violations": [d for d, _ in bad]},
        "warnings": warns,
    }
    (DIST / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=1), "utf-8")

    n_user = sum(1 for r in rules if r.action == "DIRECT" and "whitelist" in r.sources)
    n_updir = sum(1 for r in rules if r.action == "DIRECT" and "whitelist" not in r.sources)
    print(f"\n构建成功（{built}）")
    for sid, n in per.items():
        print(f"  源 {sid:12s} 解析 {n:6d} 条（跳过 {skipped.get(sid, 0)} 行）")
    print(f"  L1 去重后 L2 吸收 {absorbed} 条 | 用户白名单 {n_user} | 上游放行 {n_updir} | 最终 {len(rules)} 条")
    print(f"  开屏改写 {len(rewrites)} 条 | MITM hostname {len(mitm_hosts)} 个 | canary {len(canaries)} 个全部通过" if not bad else "")
    for name in outs:
        size = (DIST / name).stat().st_size
        print(f"  → dist/{name}（{size / 1024:.0f} KB）")
    return 0


def cmd_explain(args):
    cfg, rw = load_cfg()
    rules, *_ = build_rules(cfg, rw, live=False)
    host = args.host.lower()
    hits = [r for r in rules if r.type != "IP-CIDR" and r.match_domain(host)]
    if not hits:
        print(f"{host}: 无任何规则命中（放行）。")
    for r in hits:
        tag = "白名单放行" if r.action == "DIRECT" else "拦截"
        print(f"  {tag}: {r.type},{r.pattern},{r.action}  来源: {'+'.join(r.sources)}")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="adkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="完整构建")
    b.add_argument("--offline", action="store_true", help="不联网，用 cache/snapshots")
    b.add_argument("--only", type=lambda s: s.split(","), default=None, help="只重新抓取这些源 id（逗号分隔），其余走 cache")
    b.add_argument("--ignore-canary", action="store_true", help="canary 失败仍发布（危险）")
    b.set_defaults(fn=cmd_build)
    e = sub.add_parser("explain", help="查询某域名会被哪条规则命中（离线，读缓存）")
    e.add_argument("host")
    e.set_defaults(fn=cmd_explain)
    args = ap.parse_args(argv)
    return args.fn(args)
