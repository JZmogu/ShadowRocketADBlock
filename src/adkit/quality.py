"""质量门：canary 金丝雀、域名合法性、CA 私钥剥离断言、计数偏移（警告）。"""
from __future__ import annotations

FORBIDDEN = ("ca-p12", "ca-passphrase", "private key")


def canary_check(rules, canaries):
    """返回 [(canary域名, 命中它的REJECT规则)]；非空即构建失败。"""
    bad = []
    for d in canaries:
        for r in rules:
            if r.is_reject() and r.match_domain(d):
                bad.append((d, r))
                break
    return bad


def count_deviation(prev: dict, cur: dict, threshold: float = 0.4):
    """per_source 计数偏移 ±40% 报警（v0.1 只警告，不阻断）。"""
    warns = []
    prev_map = (prev or {}).get("per_source", {})
    cur_map = (cur or {}).get("per_source", {})
    for sid, n in cur_map.items():
        p = prev_map.get(sid)
        if p and abs(n - p) / p > threshold:
            warns.append(f"源 {sid} 规则数 {p} -> {n}（偏移超过 {threshold:.0%}，请人工核查上游是否被投毒/改版）")
    return warns


def scrub_assert(text: str):
    low = text.lower()
    for token in FORBIDDEN:
        if token in low:
            raise AssertionError(f"产物中出现违禁内容 {token!r}，拒绝发布")
