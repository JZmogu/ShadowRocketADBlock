import gzip
import pathlib
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from adkit import merge, render  # noqa: E402
from adkit.ir import Rule  # noqa: E402
from adkit.parsers import PARSERS, parse_sr_conf_rule, parse_surge_list  # noqa: E402


class ParserRegressionTest(unittest.TestCase):
    def test_ip_unknown_policy_is_not_reject(self):
        for parser in (parse_surge_list, parse_sr_conf_rule):
            for policy in ("PROXY", "代理组", "UNKNOWN", "REJECT-MADE-UP"):
                with self.subTest(parser=parser.__name__, policy=policy):
                    rules, skipped = parser(f"IP-CIDR,91.108.4.0/22,{policy},no-resolve", "test")
                    self.assertEqual((rules, skipped), ([], 1))

    def test_omitted_ip_action_and_modifiers_default_to_reject(self):
        for suffix in ("", ",no-resolve", ",important,no-resolve"):
            with self.subTest(suffix=suffix):
                rules, skipped = parse_surge_list("IP-CIDR,192.0.2.0/24" + suffix, "test")
                self.assertEqual(skipped, 0)
                self.assertEqual(rules[0].action, "REJECT")

    def test_explicit_unknown_or_duplicate_actions_do_not_default(self):
        for tail in (",", ",PROXY,REJECT", ",REJECT,DIRECT", ",DIRECT,unknown-option"):
            with self.subTest(tail=tail):
                self.assertEqual(parse_surge_list("IP-CIDR,192.0.2.0/24" + tail, "test"), ([], 1))

    def test_cidr_validity_and_address_family(self):
        for line in (
            "IP-CIDR,garbage,REJECT",
            "IP-CIDR,192.0.2.0/33,REJECT",
            "IP-CIDR,2001:db8::/32,REJECT",
            "IP-CIDR6,192.0.2.0/24,REJECT",
        ):
            with self.subTest(line=line):
                self.assertEqual(parse_surge_list(line, "test"), ([], 1))
        rules, _ = parse_surge_list("IP-CIDR6,2001:db8::/32,DIRECT,no-resolve", "test")
        self.assertEqual((rules[0].pattern, rules[0].action), ("2001:db8::/32", "DIRECT"))

    def test_url_regex_preserves_internal_commas(self):
        patterns = (
            r"^https://ad[0-9]{1,3}\.example\.com/",
            r"^https://ads\.example\.com/(a,b)/[x,y]",
            r"^https://ads\.example\.com/a\,b",
            r"^https://ads\.example\.com/a,b",
        )
        for parser in (parse_surge_list, parse_sr_conf_rule):
            for pattern in patterns:
                with self.subTest(parser=parser.__name__, pattern=pattern):
                    rules, skipped = parser(f"URL-REGEX,{pattern},REJECT,important", "test")
                    self.assertEqual(skipped, 0)
                    self.assertEqual((rules[0].pattern, rules[0].action), (pattern, "REJECT"))

    def test_url_regex_without_action_and_with_quantifier(self):
        pattern = r"^https://ad[0-9]{1,3}\.example\.com/"
        rules, skipped = parse_surge_list(f"URL-REGEX,{pattern}", "test")
        self.assertEqual(skipped, 0)
        self.assertEqual((rules[0].pattern, rules[0].action), (pattern, "REJECT"))

    def test_url_regex_unknown_policy_and_invalid_regex_are_skipped(self):
        for line in (
            r"URL-REGEX,^https://ad[0-9]{1,3}\.example\.com/,PROXY",
            "URL-REGEX,[broken,REJECT",
            "DOMAIN-KEYWORD,,REJECT",
        ):
            with self.subTest(line=line):
                self.assertEqual(parse_surge_list(line, "test"), ([], 1))


def first_action(rules, host):
    return next((r.action for r in render.ordered_rules(rules) if r.match_domain(host)), None)


class AbsorptionRegressionTest(unittest.TestCase):
    def test_exact_rule_keeps_priority_over_other_action_suffix(self):
        rules = [
            Rule("DOMAIN", "a.x.com", "REJECT", ["exact"]),
            Rule("DOMAIN-SUFFIX", "x.com", "REJECT", ["parent"]),
            Rule("DOMAIN-SUFFIX", "a.x.com", "REJECT-DICT", ["response"]),
        ]
        result, dropped = merge.absorb(rules)
        self.assertEqual(dropped, 0)
        self.assertEqual(first_action(rules, "a.x.com"), "REJECT")
        self.assertEqual(first_action(result, "a.x.com"), "REJECT")

    def test_same_pattern_conflict_keeps_original_action_order(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "x.com", "REJECT", ["parent"]),
            Rule("DOMAIN-SUFFIX", "a.x.com", "REJECT", ["child"]),
            Rule("DOMAIN-SUFFIX", "a.x.com", "REJECT-200", ["other"]),
        ]
        result, _ = merge.absorb(rules)
        for host in ("a.x.com", "child.a.x.com"):
            with self.subTest(host=host):
                self.assertEqual(first_action(result, host), first_action(rules, host))

    def test_unrelated_different_action_does_not_block_absorption(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "x.com", "REJECT", ["parent"]),
            Rule("DOMAIN", "a.x.com", "REJECT", ["child"]),
            Rule("DOMAIN-SUFFIX", "unrelated.com", "REJECT-DICT", ["other"]),
        ]
        result, dropped = merge.absorb(rules)
        self.assertEqual(dropped, 1)
        self.assertEqual(first_action(result, "a.x.com"), "REJECT")

    def test_whitelist_priority_is_never_absorbed_into_upstream_direct(self):
        rules = [
            Rule("DOMAIN-SUFFIX", "a.x.com", "DIRECT", ["whitelist"]),
            Rule("DOMAIN-SUFFIX", "x.com", "DIRECT", ["upstream"]),
            Rule("IP-CIDR", "192.0.2.0/24", "REJECT", ["upstream"]),
        ]
        result, _ = merge.absorb(rules)
        self.assertTrue(any("whitelist" in r.sources for r in result))


class SnapshotRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = tomllib.loads((ROOT / "config/sources.toml").read_text())
        rules = []
        for source in cfg["sources"]:
            raw = gzip.decompress((ROOT / "snapshots" / f"{source['id']}.gz").read_bytes()).decode("utf-8")
            parsed, _ = PARSERS[source["parser"]](raw, source["id"])
            rules.extend(parsed)
        cls.before = merge.dedup(rules)
        cls.after, _ = merge.absorb(cls.before)

    def test_snapshot_proxy_networks_do_not_become_reject(self):
        raw = gzip.decompress((ROOT / "snapshots/huijingfei.gz").read_bytes()).decode("utf-8")
        proxy_networks = []
        for line in raw.splitlines():
            fields = [p.strip() for p in line.split(",")]
            if len(fields) > 2 and fields[0] in ("IP-CIDR", "IP-CIDR6") and fields[2] == "PROXY":
                proxy_networks.append((fields[0], fields[1]))
        self.assertEqual(len(proxy_networks), 15)
        rejected = {(r.type, r.pattern) for r in self.after if r.is_reject()}
        self.assertTrue(rejected.isdisjoint(proxy_networks))

    def test_snapshot_umeng_actions_survive_absorption(self):
        for host in (
            "cnlogs.umeng.com", "cnlogs.umengcloud.com", "resolve.umeng.com",
            "ulogs.umeng.com", "ulogs.umengcloud.com",
        ):
            with self.subTest(host=host):
                self.assertEqual(first_action(self.before, host), "REJECT")
                self.assertEqual(first_action(self.after, host), "REJECT")


if __name__ == "__main__":
    unittest.main()
