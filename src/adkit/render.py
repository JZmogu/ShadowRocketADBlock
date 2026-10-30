"""渲染器（v0.1 只做 SR）：一键订阅全量配置 + 纯规则文件。"""
from __future__ import annotations

TYPE_ORDER = {"URL-REGEX": 0, "DOMAIN-KEYWORD": 1, "DOMAIN": 2, "DOMAIN-SUFFIX": 3, "IP-CIDR": 4, "IP-CIDR6": 5}


def _fmt(r) -> str:
    if r.type in ("IP-CIDR", "IP-CIDR6"):
        return f"{r.type},{r.pattern},{r.action},no-resolve"
    return f"{r.type},{r.pattern},{r.action}"


def ordered_rules(rules) -> list:
    """渲染、检查和 explain 共用的首条匹配顺序。"""
    user_wl = [r for r in rules if r.action == "DIRECT" and "whitelist" in r.sources]
    rest = [r for r in rules if r.action != "DIRECT"]
    updir = [r for r in rules if r.action == "DIRECT" and "whitelist" not in r.sources]
    key = lambda r: (TYPE_ORDER.get(r.type, 9), r.pattern)
    rest.sort(key=key)
    updir.sort(key=key)
    return user_wl + rest + updir


def _rule_lines(rules) -> list[str]:
    ordered = ordered_rules(rules)
    user_wl = [r for r in ordered if r.action == "DIRECT" and "whitelist" in r.sources]
    rest = [r for r in ordered if r.action != "DIRECT"]
    updir = [r for r in ordered if r.action == "DIRECT" and "whitelist" not in r.sources]
    out = ["# ==== 用户白名单例外区（最高优先级，DIRECT）===="]
    out += [_fmt(r) for r in user_wl]
    out.append("")
    out.append("# ==== 广告拦截规则 ====")
    out += [_fmt(r) for r in rest]
    out.append("")
    out.append("# ==== DIRECT 路由规则 ====")
    out += [_fmt(r) for r in updir]
    return out


def render_full_conf(rules, rewrites, mitm_hosts, update_url, header) -> str:
    lines = [header, "", "[General]", f"update-url = {update_url}",
             "always-reject-url-rewrite = true", ""]
    lines.append("[Rule]")
    lines += _rule_lines(rules)
    if rewrites:
        lines += ["", "[URL Rewrite]"]
        for w in rewrites:
            lines.append(f'{w["pattern"]} {w["target"]} {w["action"]}')
    if mitm_hosts:
        lines += ["", "[MITM]", "enable = true", "hostname = " + ",".join(sorted(mitm_hosts))]
    return "\n".join(lines) + "\n"


def render_adonly(rules, header) -> str:
    lines = [header, "", "[Rule]"] + _rule_lines(rules)
    return "\n".join(lines) + "\n"


def _module_sections(rewrites, mitm_hosts):
    lines = []
    if rewrites:
        lines += ["", "[URL Rewrite]"]
        lines += [f'{w["pattern"]} {w["target"]} {w["action"]}' for w in rewrites]
    if mitm_hosts:
        lines += ["", "[MITM]", "enable = true",
                  "hostname = %APPEND% " + ",".join(sorted(mitm_hosts))]
    return lines


def render_module(rules, rewrites, mitm_hosts, header) -> str:
    """在现有主配置上附加规则；保留已有节点和 hostname。"""
    lines = ["#!name=去广告 adkit", "#!desc=广告规则与 URL 改写；HTTPS 需要当前配置的证书", "", header,
             "", "[Rule]"]
    lines += _rule_lines(rules)
    lines += _module_sections(rewrites, mitm_hosts)
    return "\n".join(lines) + "\n"


def render_lite_module(rewrites, mitm_hosts, header) -> str:
    """仅 URL 改写与 MITM；域名规则需要另外加载。"""
    lines = ["#!name=去广告-开屏改写", "#!desc=URL 改写；需另外加载域名规则", "", header]
    lines += _module_sections(rewrites, mitm_hosts)
    return "\n".join(lines) + "\n"
