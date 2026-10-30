"""按源写死的解析器。原则：认不出的行跳过并计数，绝不瞎猜动作。"""
from __future__ import annotations

import ipaddress
import re

from .ir import DOMAIN, IPCIDR, KEYWORD, Rule, SUFFIX, URLREGEX, domain_sane, norm_domain

KNOWN = {"REJECT", "DIRECT", "REJECT-200", "REJECT-DICT", "REJECT-DICT-200", "REJECT-IMG", "REJECT-VIDEO", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"}
MODIFIERS = {"NO-RESOLVE", "IMPORTANT"}


def _norm_action(raw: str):
    a = raw.strip().upper()
    if a in MODIFIERS:
        return None  # 修饰符，不是动作
    if a in KNOWN:
        return a
    return None  # 未知策略（代理组名等）→ 调用方跳过该规则


def _action(fields):
    """只有未提供动作时默认拦截；显式未知策略不能变成 REJECT。"""
    actions = []
    for field in fields:
        if field.upper() in MODIFIERS:
            continue
        action = _norm_action(field)
        if action is None:
            return None
        actions.append(action)
    if len(actions) > 1:
        return None
    return actions[0] if actions else "REJECT"


def _parts(line):
    """URL 正则的量词、字符类、分组和转义逗号不属于字段分隔符。"""
    rule_type, sep, body = line.partition(",")
    if not sep or rule_type.strip().upper() != URLREGEX:
        return [p.strip() for p in line.split(",")]
    boundaries = []
    escaped, in_class, braces, parens = False, False, 0, 0
    for i, char in enumerate(body):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[" and not in_class:
            in_class = True
        elif char == "]" and in_class:
            in_class = False
        elif not in_class:
            if char == "{":
                braces += 1
            elif char == "}" and braces:
                braces -= 1
            elif char == "(":
                parens += 1
            elif char == ")" and parens:
                parens -= 1
            elif char == "," and not braces and not parens:
                boundaries.append(i)
    # 动作和修饰符从右侧读取，正则中其他顶层逗号保持原样。
    fields = []
    end = len(body)
    while boundaries:
        split = boundaries.pop()
        field = body[split + 1:end].strip()
        fields.insert(0, field)
        end = split
        if field.upper() not in MODIFIERS:
            break
    return [rule_type.strip(), body[:end].strip(), *fields]


def _mk(t: str, parts, sid: str):
    pat = norm_domain(parts[1])
    if t == KEYWORD:
        pat = parts[1].strip().lower()
        if not pat or any(char.isspace() for char in pat):
            return None
    if t in (DOMAIN, SUFFIX) and not domain_sane(pat):
        return None
    if t == SUFFIX and "." not in pat:
        t = DOMAIN  # 单标签域名（hosts 垃圾）降级为精确匹配
    if t in (IPCIDR, "IP-CIDR6"):
        try:
            network = ipaddress.ip_network(parts[1], strict=False)
        except ValueError:
            return None
        if network.version != (4 if t == IPCIDR else 6):
            return None
        pat = str(network)
    elif t == URLREGEX:
        pat = parts[1]
        if not pat:
            return None
        try:
            re.compile(pat)
        except re.error:
            return None
    elif t not in (DOMAIN, SUFFIX, KEYWORD):
        return None
    act = _action(parts[2:])
    if act is None:
        return None
    return Rule(t, pat, act, [sid])


def parse_surge_list(text: str, sid: str):
    rules, skipped = [], 0
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln[0] in "#![]":
            continue
        parts = _parts(ln)
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
        parts = _parts(s)
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
