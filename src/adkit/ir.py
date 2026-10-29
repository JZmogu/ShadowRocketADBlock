"""统一中间表示（IR）。所有源解析成 Rule，去重/吸收/白名单/canary 都在这一层做。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

DOMAIN = "DOMAIN"
SUFFIX = "DOMAIN-SUFFIX"
KEYWORD = "DOMAIN-KEYWORD"
URLREGEX = "URL-REGEX"
IPCIDR = "IP-CIDR"

_DOMAIN_RE = re.compile(r"^[a-z0-9.\-]+$")


@dataclass
class Rule:
    type: str
    pattern: str
    action: str  # REJECT / REJECT-200 / REJECT-DICT / REJECT-IMG / REJECT-VIDEO / DIRECT ...
    sources: list = field(default_factory=list)

    def key(self):
        return (self.type, self.pattern, self.action)

    def is_reject(self) -> bool:
        return self.action.startswith("REJECT")

    def match_domain(self, host: str) -> bool:
        h = host.lower().strip(".")
        if self.type == DOMAIN:
            return h == self.pattern
        if self.type == SUFFIX:
            return h == self.pattern or h.endswith("." + self.pattern)
        if self.type == KEYWORD:
            return self.pattern in h
        return False


def norm_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".").lstrip("*").lstrip(".")
    return d


def domain_sane(d: str) -> bool:
    return bool(d) and bool(_DOMAIN_RE.match(d)) and ".." not in d and not d.startswith(".")
