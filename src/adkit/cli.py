"""adkit 命令行：build（抓取→解析→去重吸收→质量门→渲染）、explain（规则归因查询）。"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import tomllib
from urllib.parse import urlsplit

from . import fetch, merge, quality, render
from .ir import Rule, domain_sane, norm_domain, SUFFIX
from .parsers import PARSERS

ROOT = pathlib.Path(__file__).resolve().parents[2]
CFG = ROOT / "config"
DIST = ROOT / "dist"


def load_cfg():
    with open(CFG / "sources.toml", "rb") as f:
        cfg = tomllib.load(f)
    with open(CFG / "rewrite.toml", "rb") as f:
        rw = tomllib.load(f)
    ids = []
    for source in cfg.get("sources", []):
        sid = source.get("id", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", sid) or sid in ids:
            raise ValueError(f"来源 id 无效或重复: {sid!r}")
        ids.append(sid)
        if source.get("parser") not in PARSERS:
            raise ValueError(f"[{sid}] 未知解析器")
        if not isinstance(source.get("min_rules", 1), int) or source.get("min_rules", 1) < 1:
            raise ValueError(f"[{sid}] min_rules 必须为正整数")
        deviation = source.get("max_deviation", 0.4)
        if not isinstance(deviation, (int, float)) or not 0 < deviation <= 1:
            raise ValueError(f"[{sid}] max_deviation 必须在 (0, 1] 范围")
    if not any(s.get("enabled", True) for s in cfg.get("sources", [])):
        raise ValueError("没有启用的规则来源")
    return cfg, rw


def load_list(path: pathlib.Path):
    out = []
    for ln in path.read_text("utf-8").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
    return out


def domain_list(path):
    domains = [norm_domain(d) for d in load_list(path)]
    for domain in domains:
        if not domain_sane(domain):
            raise ValueError(f"{path.name} 中的域名无效: {domain!r}")
    return list(dict.fromkeys(domains))


def url_canaries():
    path = CFG / "canary_urls.txt"
    urls = load_list(path) if path.exists() else []
    for url in urls:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"canary_urls.txt 中的 URL 无效: {url!r}")
    return urls


def build_rules(cfg, rw, live: bool, only_ids=None, pending=None, source_hashes=None,
                check_canaries=True):
    enabled_ids = {s["id"] for s in cfg["sources"] if s.get("enabled", True)}
    if only_ids and set(only_ids) - enabled_ids:
        raise ValueError(f"--only 包含未知或停用来源: {sorted(set(only_ids) - enabled_ids)}")
    wl_rules = [Rule(SUFFIX, d, "DIRECT", ["whitelist"]) for d in domain_list(CFG / "whitelist.txt")]
    user_rules, user_skipped, user_text = [], 0, None
    user_path = CFG / "user_rules.txt"
    if user_path.exists():
        user_text = user_path.read_text("utf-8")
        user_rules, user_skipped = PARSERS["sr_conf_rule"](user_text, "user")
        if user_skipped:
            raise ValueError(f"user_rules.txt 有 {user_skipped} 条无效规则，请修正后构建")
        for rule in user_rules:
            if rule.action == "DIRECT":
                rule.sources.append("whitelist")
    direct = wl_rules + [r for r in user_rules if r.action == "DIRECT"]
    canaries = domain_list(CFG / "canary.txt")
    urls = url_canaries()

    def validate_source(source, text):
        if not check_canaries:
            return
        source_rules, _ = PARSERS[source["parser"]](text, source["id"])
        bad = quality.canary_check(direct + source_rules, canaries)
        url_bad = quality.url_canary_check(direct + source_rules, [], urls)
        if bad or url_bad:
            details = [f"{d}: {r.type},{r.pattern},{r.action}" for d, r in bad]
            raise ValueError("金丝雀失败: " + "; ".join((details + url_bad)[:5]))

    texts = fetch.load_sources(cfg, ROOT / "cache", ROOT / "snapshots", live=live,
                               only_ids=only_ids, pending=pending, validate=validate_source)
    all_rules, per, skipped, warns = [], {}, {}, []
    missing = []
    for sid, text, warn in texts:
        src = next(s for s in cfg["sources"] if s["id"] == sid)
        if text is None:
            per[sid] = 0
            warns.append(f"[{sid}] 源完全失败（无快照可用）: {warn}")
            missing.append(sid)
            continue
        if warn:
            warns.append(f"[{sid}] {warn}")
        rules, sk = PARSERS[src["parser"]](text, sid)
        all_rules.extend(rules)
        per[sid] = len(rules)
        skipped[sid] = sk
        if source_hashes is not None:
            source_hashes[sid] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if missing:
        raise ValueError("缺少有效规则副本，停止构建: " + "; ".join(warns))
    if user_text is not None:
        all_rules.extend(user_rules)
        per["user"] = len(user_rules)
        skipped["user"] = user_skipped
        if source_hashes is not None:
            source_hashes["user"] = hashlib.sha256(user_text.encode()).hexdigest()
    all_rules, ip_dropped = merge.screen(all_rules)
    if ip_dropped:
        warns.append(f"IP 过滤：剔除 {ip_dropped} 条 IP 拦截或过宽公网 DIRECT 规则")
    merged = merge.dedup(all_rules)
    merged, absorbed = merge.absorb(merged)
    return wl_rules + merged, per, skipped, absorbed, warns


def cmd_build(args):
    cfg, rw = load_cfg()
    rewrites = [w for w in rw.get("rewrite", []) if w.get("enabled", True)]
    mitm_hosts = rw.get("mitm", {}).get("hosts", [])
    errors = quality.rewrite_check(rewrites, mitm_hosts)
    if errors:
        raise ValueError("改写登记表检查失败:\n" + "\n".join(errors))
    pending, source_hashes = {}, {}
    rules, per, skipped, absorbed, warns = build_rules(
        cfg, rw, live=not args.offline, only_ids=args.only, pending=pending,
        source_hashes=source_hashes, check_canaries=not args.ignore_canary,
    )
    for w in warns:
        print("警告:", w)
    total = sum(per.values())
    minimum = cfg["meta"].get("min_total_rules", 5000)
    if total < minimum:
        print(f"错误：解析总量仅 {total} 条，低于下限 {minimum}，拒绝发布")
        return 2

    canaries = domain_list(CFG / "canary.txt")
    bad = quality.canary_check(rules, canaries)
    urls = url_canaries()
    url_bad = quality.url_canary_check(rules, rewrites, urls)
    if bad or url_bad:
        print(f"错误：金丝雀检查失败：域名 {len(bad)} 处，URL {len(url_bad)} 处：")
        for d, r in bad[:40]:
            print(f"  ✗ {d} 被规则 [{r.type},{r.pattern},{r.action}]（来源: {'+'.join(r.sources)}）拦截")
        for detail in url_bad[:40]:
            print("  ✗", detail)
        if not args.ignore_canary:
            print("构建终止，保留已发布版本。域名误拦可调整白名单；URL 误拦需调整对应改写或 URL 规则。")
            return 2
        print("--ignore-canary：仅生成本地排查产物，不更新有效快照；stats 标记为未通过。")

    prev_stats = None
    if (DIST / "stats.json").exists():
        prev_stats = json.loads((DIST / "stats.json").read_text("utf-8"))
        for w in quality.count_deviation(prev_stats, {"per_source": per}):
            print("警告:", w)
            warns.append(w)

    built = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    src_names = "; ".join(s["id"] + " (" + s.get("license", "?") + ")" for s in cfg["sources"] if s.get("enabled", True))
    header = (
        "# ShadowRocketADBlock —— adkit 自动构建产物，请勿手改\n"
        "# 白名单: config/whitelist.txt | 开屏改写: config/rewrite.toml | 源开关: config/sources.toml\n"
        f"# 构建(UTC): {built} | adkit v0.1\n"
        f"# 规则出处及许可: {src_names}\n"
        "# 本文件不含任何 CA/私钥；HTTPS 解密使用当前配置中你自己的证书"
    )

    outs = {
        "stable/adkit.conf": render.render_full_conf(rules, rewrites, mitm_hosts, cfg["meta"]["stable_url"], header),
        "latest/adkit.conf": render.render_full_conf(rules, rewrites, mitm_hosts, cfg["meta"]["latest_url"], header),
        "adkit-adonly.conf": render.render_adonly(rules, header),
        "stable/adkit.module": render.render_module(rules, rewrites, mitm_hosts, header),
        "latest/adkit.module": render.render_module(rules, rewrites, mitm_hosts, header),
        "stable/adkit-lite.module": render.render_lite_module(rewrites, mitm_hosts, header),
        "latest/adkit-lite.module": render.render_lite_module(rewrites, mitm_hosts, header),
    }
    for name, text in outs.items():
        quality.scrub_assert(text)

    DIST.mkdir(exist_ok=True)
    for name, text in outs.items():
        p = DIST / name
        p.parent.mkdir(parents=True, exist_ok=True)
        temporary = p.with_suffix(".tmp")
        temporary.write_text(text, "utf-8")
        temporary.replace(p)

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
        "url_canary": {"size": len(urls), "violations": url_bad},
        "quality_passed": not (bad or url_bad),
        "input_sha256": source_hashes,
        "source_commit": os.environ.get("GITHUB_SHA"),
    }
    (DIST / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=1), "utf-8")
    if not args.offline and stats["quality_passed"]:
        fetch.commit_sources(pending, ROOT / "cache", ROOT / "snapshots")

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
    rules, *_, warns = build_rules(cfg, rw, live=False, check_canaries=False)
    host = args.host.strip()
    is_url = host.startswith(("http://", "https://"))
    hits = [r for r in render.ordered_rules(rules)
            if (r.match_url(host) if is_url else r.match_domain(host) or r.match_ip(host))]
    print("本地规则查询；设备上生效的版本和路由模式可能不同。")
    if not hits:
        print(f"{host}: 无路由规则命中，使用客户端默认路由。")
    for index, r in enumerate(hits):
        tag = "最终路由匹配" if index == 0 else "被前序规则覆盖"
        print(f"  {tag}: {r.type},{r.pattern},{r.action}  来源: {'+'.join(r.sources)}")
    if is_url:
        import re
        for w in rw.get("rewrite", []):
            if w.get("enabled", True) and re.search(w["pattern"], host):
                print(f"  首条 URL 改写: {w['site']} -> {w['action']}；HTTPS 还需解密和证书信任")
                break
    else:
        print("提供完整 http(s) URL 才能查询 URL 正则及人工改写。")
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
    try:
        return args.fn(args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"错误：{exc}")
        return 2
