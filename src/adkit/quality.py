"""质量门：canary 金丝雀、域名合法性、CA 私钥剥离断言、计数偏移（警告）。"""
from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlsplit

from .ir import URLREGEX, domain_sane
from .render import ordered_rules

FORBIDDEN = ("ca-p12", "ca-passphrase", "private key")
REWRITE_ACTIONS = {"301", "302", "303", "307", "308", "REJECT", "REJECT-200",
                   "REJECT-DICT", "REJECT-DICT-200", "REJECT-IMG", "REJECT-VIDEO"}


def canary_check(rules, canaries):
    """按实际渲染顺序检查首条域名匹配；用户白名单可以覆盖拦截。"""
    bad = []
    ordered = ordered_rules(rules)
    for d in canaries:
        for r in ordered:
            if r.match_domain(d):
                if r.is_reject():
                    bad.append((d, r))
                break
    return bad


def url_canary_check(rules, rewrites, urls):
    """检查代表性良性 URL；域名白名单不豁免独立的 URL 改写。"""
    bad = []
    ordered = ordered_rules(rules)
    for url in urls:
        for rule in ordered:
            if rule.match_url(url):
                if rule.is_reject():
                    bad.append(f"{url} 被 {rule.type},{rule.pattern},{rule.action} 命中")
                break
        for rewrite in rewrites:
            if rewrite.get("enabled", True) and re.search(rewrite["pattern"], url):
                if rewrite["action"].startswith("REJECT"):
                    bad.append(f"{url} 被改写 {rewrite.get('site', rewrite['pattern'])} 命中")
                break
    return bad


def mitm_host_sane(host):
    """允许主机名中的 * / ? 通配符，不接受 fnmatch 字符类等额外语法。"""
    return (
        isinstance(host, str) and host == host.lower()
        and re.fullmatch(r"[a-z0-9.*?\-]+", host) is not None
        and re.search(r"[a-z0-9]", host) is not None
        and domain_sane(host.replace("*", "a").replace("?", "a"))
    )


def _url_samples_check(entry, regex, label, mitm_hosts):
    errors = []
    for field in ("example_urls", "allow_urls"):
        samples = entry.get(field)
        if not isinstance(samples, list) or not samples:
            errors.append(f"{label}: 缺少 {field} 示例")
            continue
        for sample in samples:
            try:
                parsed = urlsplit(sample) if isinstance(sample, str) else None
                valid = parsed and parsed.scheme in ("http", "https") and parsed.hostname
            except ValueError:
                valid = False
            if not valid:
                errors.append(f"{label}: 无效 URL 示例 {sample!r}")
                continue
            matches = regex.search(sample) is not None
            if field == "example_urls":
                if not matches:
                    errors.append(f"{label}: 正例未匹配 {sample}")
                # HTTP 正例不能绕过支持 HTTPS 的同一规则的主机检查。
                https_sample = parsed._replace(scheme="https").geturl()
                if regex.search(https_sample) and not any(
                    fnmatch.fnmatchcase(parsed.hostname, h) for h in mitm_hosts
                ):
                    errors.append(f"{label}: HTTPS 正例缺少 MITM hostname: {parsed.hostname}")
            elif matches:
                errors.append(f"{label}: 负例被误匹配 {sample}")
    return errors


def rewrite_check(rewrites, mitm_hosts):
    """验证登记表与示例；正反例不代表完整的客户端兼容性验证。"""
    errors = []
    for host in mitm_hosts:
        if not mitm_host_sane(host):
            errors.append(f"无效 MITM hostname: {host}")
    for index, rewrite in enumerate(rewrites, 1):
        if not rewrite.get("enabled", True):
            continue
        label = rewrite.get("site", f"改写 #{index}")
        pattern, action, target = (rewrite.get(k) for k in ("pattern", "action", "target"))
        if not all(isinstance(v, str) and v and "\n" not in v and "\r" not in v
                   for v in (pattern, action, target)):
            errors.append(f"{label}: pattern/action/target 必须是非空单行文本")
            continue
        if action not in REWRITE_ACTIONS:
            errors.append(f"{label}: 不支持的改写动作 {action}")
        if action.startswith("REJECT") and target != "_":
            errors.append(f"{label}: REJECT 的 target 必须为 _")
        if action.isdigit() and not target.startswith(("http://", "https://")):
            errors.append(f"{label}: 重定向目标必须为 HTTP(S) URL")
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            errors.append(f"{label}: 正则无效: {exc}")
            continue
        errors.extend(_url_samples_check(rewrite, regex, label, mitm_hosts))
    return errors


def url_rule_check(rules, registry, mitm_hosts):
    """每条实际使用的 URL-REGEX 都必须有已审查的样例及 HTTPS 解密覆盖。"""
    errors, registered = [], {}
    if not isinstance(registry, list):
        return ["URL 规则登记必须是 url_rule 表列表"]
    for entry in registry:
        if not isinstance(entry, dict):
            errors.append("URL 规则登记必须是表")
            continue
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            errors.append("URL 规则登记缺少 pattern")
        elif pattern in registered:
            errors.append(f"URL 规则重复登记: {pattern}")
        else:
            registered[pattern] = entry
    checked = set()
    for rule in rules:
        if rule.type != URLREGEX or rule.pattern in checked:
            continue
        checked.add(rule.pattern)
        entry = registered.get(rule.pattern)
        if entry is None:
            errors.append(f"URL-REGEX 未登记样例: {rule.pattern}（来源: {'+'.join(rule.sources)}）")
            continue
        label = entry.get("site", rule.pattern)
        errors.extend(_url_samples_check(entry, re.compile(rule.pattern), label, mitm_hosts))
    return errors


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
