"""按源写死的解析器。原则：认不出的行跳过并计数，绝不瞎猜动作。"""
from __future__ import annotations

from .ir import DOMAIN, IPCIDR, KEYWORD, Rule, SUFFIX, URLREGEX, domain_sane, norm_domain

KNOWN = {"REJECT", "DIRECT"}


def _norm_action(raw: str):
    a = raw.strip().upper()
    if a in ("NO-RESOLVE", "IMPORTANT"):
        return None  # 修饰符，不是动作
    if a in KNOWN or a.startswith("REJECT-"):
        return a
    return None  # 未知策略（代理组名等）→ 调用方跳过该规则


def _mk(t: str, parts, sid: str):
    pat = norm_domain(parts[1])
    if t == KEYWORD:
        pat = parts[1].strip().lower()
    if t in (DOMAIN, SUFFIX) and not domain_sane(pat):
        return None
    if t == SUFFIX and "." not in pat:
        t = DOMAIN  # 单标签域名（hosts 垃圾）降级为精确匹配
    if t in (DOMAIN, SUFFIX, KEYWORD):
        act = _norm_action(parts[2]) if len(parts) > 2 else "REJECT"
    elif t in (IPCIDR, "IP-CIDR6"):
        act = "REJECT"
        for p in parts[2:]:
            na = _norm_action(p)
            if na:
                act = na
                break
    elif t == URLREGEX:
        act = _norm_action(parts[2]) if len(parts) > 2 else "REJECT"
        pat = parts[1]
    else:
        return None
    if act is None:
        return None
    return Rule(t, pat, act, [sid])


def parse_surge_list(text: str, sid: str):
    rules, skipped = [], 0
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln[0] in "#![]":
            continue
        parts = [p.strip() for p in ln.split(",")]
        t = parts[0].upper()
        if len(parts) < 2:
            skipped += 1
            continue
        r = _mk(t, parts, sid)
        if r:
            rules.append(r)
        else:
            skipped += 1
    return rules, skipped


def parse_sr_conf_rule(text: str, sid: str):
    """SR 配置：若存在 [Rule] 段则只取该段；若整文件无段头（纯规则文件）则全取。"""
    lines = text.splitlines()
    has_section = any(ln.strip().startswith("[") and ln.strip().endswith("]") for ln in lines)
    rules, skipped, in_rule = [], 0, not has_section
    for ln in lines:
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            in_rule = s.lower() == "[rule]"
            continue
        if not in_rule or not s or s[0] == "#":
            continue
        parts = [p.strip() for p in s.split(",")]
        t = parts[0].upper()
        if t in ("FINAL", "MATCH") or len(parts) < 2:
            continue
        r = _mk(t, parts, sid)
        if r:
            rules.append(r)
        else:
            skipped += 1
    return rules, skipped


PARSERS = {"surge_list": parse_surge_list, "sr_conf_rule": parse_sr_conf_rule}
