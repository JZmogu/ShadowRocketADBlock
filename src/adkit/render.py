"""渲染器（v0.1 只做 SR）：一键订阅全量配置 + 纯规则文件。"""
from __future__ import annotations

TYPE_ORDER = {"URL-REGEX": 0, "DOMAIN-KEYWORD": 1, "DOMAIN": 2, "DOMAIN-SUFFIX": 3, "IP-CIDR": 4, "IP-CIDR6": 5}


def _fmt(r) -> str:
    if r.type in ("IP-CIDR", "IP-CIDR6"):
        return f"{r.type},{r.pattern},{r.action},no-resolve"
    return f"{r.type},{r.pattern},{r.action}"


def _rule_lines(rules) -> list[str]:
    # SR 是 first-match：用户白名单最前；精确 REJECT 主区居中；上游宽泛 DIRECT 垫底兜底。
    user_wl = [r for r in rules if r.action == "DIRECT" and "whitelist" in r.sources]
    rest = [r for r in rules if r.action != "DIRECT"]
    updir = [r for r in rules if r.action == "DIRECT" and "whitelist" not in r.sources]
    key = lambda r: (TYPE_ORDER.get(r.type, 9), r.pattern)
    rest.sort(key=key)
    updir.sort(key=key)
    out = ["# ==== 用户白名单例外区（最高优先级，DIRECT）===="]
    out += [_fmt(r) for r in user_wl]
    out.append("")
    out.append("# ==== 广告拦截主区：精确强规则 → 域名 → IP（已去重吸收；优先于下方宽泛 DIRECT）====")
    out += [_fmt(r) for r in rest]
    out.append("")
    out.append("# ==== 上游精选放行（DIRECT 兜底：上面未拦截的国内常用域直连，省代理流量）====")
    out += [_fmt(r) for r in updir]
    return out


def render_full_conf(rules, rewrites, mitm_hosts, update_url, header) -> str:
    lines = [header, "", "[General]", f"update-url = {update_url}", ""]
    lines.append("[Rule]")
    lines += _rule_lines(rules)
    if rewrites:
        lines += ["", "[URL Rewrite]"]
        for w in rewrites:
            lines.append(f'{w["pattern"]} {w["target"]} {w["action"]}')
    if mitm_hosts:
        lines += ["", "[MITM]", "hostname = " + ",".join(sorted(mitm_hosts))]
    return "\n".join(lines) + "\n"


def render_adonly(rules, header) -> str:
    lines = [header, "", "[Rule]"] + _rule_lines(rules)
    return "\n".join(lines) + "\n"


def render_module(rules, rewrites, mitm_hosts, header) -> str:
    """SR 模块（.module）：叠加进用户现有配置，不动机场节点——推荐主用法。
    规则/改写/MITM 三段一次带上；无 [General]/无 update-url（远程模块 URL 本身就是更新通道）。"""
    lines = [
        "#!name=去广告 adkit",
        "#!desc=广告拦截(规则+开屏改写+MITM)。不含节点、不改你已有配置；节点仍归你的机场订阅",
        "",
        header,
        "",
        "[Rule]",
    ]
    lines += _rule_lines(rules)
    if rewrites:
        lines += ["", "[URL Rewrite]"]
        for w in rewrites:
            lines.append(f'{w["pattern"]} {w["target"]} {w["action"]}')
    if mitm_hosts:
        # %APPEND%：与主配置/其他模块的 hostname 合并而非互相覆盖（SR/Surge 模块机制）
        lines += ["", "[MITM]", "hostname = %APPEND% " + ",".join(sorted(mitm_hosts))]
    return "\n".join(lines) + "\n"


def render_lite_module(rewrites, mitm_hosts, header) -> str:
    """拆分用轻量模块：只含 [URL Rewrite]+[MITM]（几 KB）。
    大规则文件走「规则」页远程子规则（adkit-adonly.conf），避免超大模块导入风险。"""
    lines = ["#!name=去广告-开屏改写", "#!desc=开屏/内嵌 API 改写+MITM 域名。需配合「规则」页的 adkit-adonly.conf 一起用", "", header]
    if rewrites:
        lines += ["", "[URL Rewrite]"]
        for w in rewrites:
            lines.append(f'{w["pattern"]} {w["target"]} {w["action"]}')
    if mitm_hosts:
        lines += ["", "[MITM]", "hostname = %APPEND% " + ",".join(sorted(mitm_hosts))]
    return "\n".join(lines) + "\n"
