"""L1 精确去重 + L2 吸收（子域⊂父域、DOMAIN⊂DOMAIN-SUFFIX），只在同动作内吸收。"""
from __future__ import annotations

from .ir import DOMAIN, Rule, SUFFIX

SPECIAL_TLD = set()  # 防误伤名单：如将来需要，禁止把这些 TLD 的二级吸收发生


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
    按域名层级升序处理（祖先必先到），祖先链查表，整体 O(n×层数)。"""
    drop = set()
    groups = {}
    for r in rules:
        if r.is_reject() or r.action == "DIRECT":
            if r.type in (DOMAIN, SUFFIX) and r.pattern not in SPECIAL_TLD:
                groups.setdefault(r.action, []).append(r)
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
            if r.type == SUFFIX and r.pattern in covered:
                drop.add(r.key())
            elif r.type == DOMAIN and "." in r.pattern and covered_by_suffix(r.pattern):
                drop.add(r.key())
    return [r for r in rules if r.key() not in drop], len(drop)
