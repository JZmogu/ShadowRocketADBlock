"""L1 精确去重 + L2 吸收（子域⊂父域、DOMAIN⊂DOMAIN-SUFFIX），只在同动作内吸收。
   另有 IP 规则消毒层：上游 IP 段大量越界（johnshall 整段 REJECT Telegram 网段）或笔误（/16 放行整片云）。"""
from __future__ import annotations

from .ir import DOMAIN, Rule, SUFFIX

SPECIAL_TLD = set()  # 防误伤名单：如将来需要，禁止把这些 TLD 的二级吸收发生

IP_TYPES = ("IP-CIDR", "IP-CIDR6")


def _private_v4(ip: str) -> bool:
    a = ip.split(".")
    try:
        if a[0] in ("10", "127"):
            return True
        if a[0] == "192" and a[1] == "168":
            return True
        if a[0] == "169" and a[1] == "254":
            return True
        if a[0] == "172" and 16 <= int(a[1]) <= 31:
            return True
    except (ValueError, IndexError):
        pass
    return False


def _priv_or_fine_v6(r) -> bool:
    """v6 规则：上游几乎全写成 IP-CIDR（应属 IP-CIDR6），按实际内容判定：
    ULA(fc00::/7)/loopback 私有保留；其余一律按"细粒度 ≥/48 的白名单才保留，大段弃"。"""
    ip, _, mask = r.pattern.partition("/")
    low = ip.lower()
    if low.startswith(("fc", "fd", "fe80", "::1")):
        return True
    try:
        return int(mask or 128) >= 48
    except ValueError:
        return False


def screen(rules):
    """IP 规则消毒：
    - REJECT* IP 规则整段丢弃：上游 IP 段目的混杂（johnshall 用 IP-CIDR 封 Telegram 全段、
      失效广告服务器 IP 等），对开屏/内嵌广告（全部走域名 API）无收益，误伤风险极大。
    - DIRECT IP 规则：保留私有网段（保护性直连）与细粒度（v4 掩码 ≥/24；v6 语义错乱的
      大段如 2001:4800::/12,DIRECT 直接弃）的放行；丢弃过宽公网大段
      （如 119.29.29.98/16 —— 上游笔误，/24 写成了 /16，放行整片腾讯云）。"""
    keep, dropped = [], 0
    for r in rules:
        if r.type in IP_TYPES:
            if r.is_reject():
                dropped += 1
                continue
            if r.action == "DIRECT":
                ip, _, mask = r.pattern.partition("/")
                if ":" in ip:  # 含冒号即 v6（上游常错写为 IP-CIDR）
                    if not _priv_or_fine_v6(r):
                        dropped += 1
                        continue
                elif not _private_v4(ip) and int(mask or 32) < 24:
                    dropped += 1
                    continue
        keep.append(r)
    return keep, dropped


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
