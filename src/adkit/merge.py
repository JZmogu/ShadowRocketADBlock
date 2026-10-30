"""L1 精确去重 + L2 吸收（子域⊂父域、DOMAIN⊂DOMAIN-SUFFIX），只在同动作内吸收。"""
from __future__ import annotations

import ipaddress

from .ir import DOMAIN, Rule, SUFFIX

SPECIAL_TLD = set()  # 防误伤名单：如将来需要，禁止把这些 TLD 的二级吸收发生

IP_TYPES = ("IP-CIDR", "IP-CIDR6")
LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128",
))


def screen(rules):
    """保留现有发布策略：剔除 IP 拦截与过宽公网 DIRECT 网段。"""
    kept, dropped = [], 0
    for rule in rules:
        if "user" in rule.sources:
            kept.append(rule)
            continue
        if rule.type in IP_TYPES:
            try:
                network = ipaddress.ip_network(rule.pattern, strict=False)
            except ValueError:
                dropped += 1
                continue
            local = any(network.version == private.version and network.subnet_of(private)
                        for private in LOCAL_NETWORKS)
            if rule.is_reject() or (rule.action == "DIRECT" and not local and
                                   network.prefixlen < (24 if network.version == 4 else 48)):
                dropped += 1
                continue
        kept.append(rule)
    return kept, dropped


def dedup(rules):
    m, order = {}, []
    for r in rules:
        k = r.key()
        if k in m:
            for s in r.sources:
                if s not in m[k].sources:
                    m[k].sources.append(s)
        else:
            m[k] = Rule(*k, sources=list(dict.fromkeys(r.sources)))
            order.append(k)
    return [m[k] for k in order]


def absorb(rules):
    """L2 吸收：同动作组内，子域 SUFFIX ⊂ 已保留父域 SUFFIX；DOMAIN ⊂ 同名/祖先 SUFFIX。
    相交域有其他动作时保留规则，避免删除后改变 first-match 的有效动作。
    祖先索引的构造与查询为 O(n×层数)，另有各动作组内的排序。"""
    drop = set()
    groups = {}
    suffix_actions, exact_actions, descendant_actions = {}, {}, {}
    for r in rules:
        if r.is_reject() or r.action == "DIRECT":
            if r.type in (DOMAIN, SUFFIX) and r.pattern not in SPECIAL_TLD:
                groups.setdefault(r.action, []).append(r)
                index = suffix_actions if r.type == SUFFIX else exact_actions
                index.setdefault(r.pattern, set()).add(r.action)
                ancestor = r.pattern
                while True:
                    descendant_actions.setdefault(ancestor, set()).add(r.action)
                    if "." not in ancestor:
                        break
                    ancestor = ancestor.split(".", 1)[1]

    def conflicting_action(rule):
        # DOMAIN 只覆盖自身，SUFFIX 还覆盖所有后代。祖先 SUFFIX 同样相交。
        local = descendant_actions if rule.type == SUFFIX else exact_actions
        if local.get(rule.pattern, set()) - {rule.action}:
            return True
        ancestor = rule.pattern
        while True:
            if suffix_actions.get(ancestor, set()) - {rule.action}:
                return True
            if "." not in ancestor:
                return False
            ancestor = ancestor.split(".", 1)[1]
    for _, rs in groups.items():
        sfx = sorted(
            {r.pattern for r in rs if r.type == SUFFIX and "." in r.pattern},
            key=lambda p: (p.count("."), p),
        )
        kept = set()
        covered = set()
        for p in sfx:
            anc = p
            hit = False
            while True:
                i = anc.find(".")
                if i < 0:
                    break
                anc = anc[i + 1:]
                if anc in kept:
                    hit = True
                    break
            if hit:
                covered.add(p)
            else:
                kept.add(p)

        def covered_by_suffix(pattern: str) -> bool:
            if pattern in kept:
                return True
            anc = pattern
            while True:
                i = anc.find(".")
                if i < 0:
                    return False
                anc = anc[i + 1:]
                if anc in kept:
                    return True

        for r in rs:
            if "whitelist" in r.sources or conflicting_action(r):
                continue
            if r.type == SUFFIX and r.pattern in covered:
                drop.add(r.key())
            elif r.type == DOMAIN and "." in r.pattern and covered_by_suffix(r.pattern):
                drop.add(r.key())
    return [r for r in rules if r.key() not in drop], len(drop)
