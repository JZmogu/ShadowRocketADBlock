"""Upstream URL-REGEX rules need reviewed samples and explicit HTTPS host coverage."""
import contextlib
import copy
import gzip
import io
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from adkit import cli, quality
from adkit.ir import Rule
from adkit.parsers import parse_sr_conf_rule


class UpstreamURLRegistryTest(unittest.TestCase):
    def setUp(self):
        self.registry = tomllib.loads((ROOT / "config/url_rules.toml").read_text("utf8"))["url_rule"]
        self.hosts = tomllib.loads((ROOT / "config/rewrite.toml").read_text("utf8"))["mitm"]["hosts"]
        text = gzip.decompress((ROOT / "snapshots/huijingfei.gz").read_bytes()).decode("utf8")
        self.rules = [r for r in parse_sr_conf_rule(text, "huijingfei")[0] if r.type == "URL-REGEX"]

    def test_snapshot_url_rules_are_registered_and_https_covered(self):
        self.assertEqual(len(self.rules), 5)
        self.assertEqual({r.pattern for r in self.rules}, {r["pattern"] for r in self.registry})
        self.assertEqual(quality.url_rule_check(self.rules, self.registry, self.hosts), [])

    def test_each_previously_missing_https_host_is_required(self):
        for host in ("m.xianqihaotianmi.org", "p*-ad-sign.byteimg.com",
                     "p*-sign.douyinpic.com", "m.xsbiquge.la"):
            with self.subTest(host=host):
                errors = quality.url_rule_check(self.rules, self.registry, [h for h in self.hosts if h != host])
                self.assertTrue(any("缺少 MITM" in error for error in errors), errors)

    def test_new_or_changed_upstream_regex_needs_review(self):
        rule = Rule("URL-REGEX", r"^https://new\.ads\.test/banner", "REJECT", ["upstream"])
        self.assertTrue(any("未登记" in error for error in quality.url_rule_check([rule], self.registry, ["new.ads.test"])))

    def test_http_only_rule_needs_no_mitm(self):
        rule = next(r for r in self.rules if r.pattern.startswith("^http:"))
        self.assertEqual(quality.url_rule_check([rule], self.registry, []), [])

    def test_http_example_does_not_hide_https_host_requirement(self):
        rule = self.rules[0]
        registry = copy.deepcopy(self.registry)
        entry = next(entry for entry in registry if entry["pattern"] == rule.pattern)
        entry["example_urls"] = [url.replace("https:", "http:") for url in entry["example_urls"]]
        self.assertTrue(any("缺少 MITM" in error for error in quality.url_rule_check([rule], registry, [])))

    def test_wrong_positive_or_matching_negative_is_rejected(self):
        registry = copy.deepcopy(self.registry)
        registry[0]["example_urls"] = ["https://m.xianqihaotianmi.org/js/app.js"]
        registry[0]["allow_urls"] = ["https://m.xianqihaotianmi.org/abcdefgh/abcdefghij.js"]
        errors = quality.url_rule_check(self.rules, registry, self.hosts)
        self.assertTrue(any("正例未匹配" in error for error in errors))
        self.assertTrue(any("负例被误匹配" in error for error in errors))

    def test_duplicate_and_malformed_registry_are_rejected(self):
        self.assertTrue(quality.url_rule_check([], self.registry + [self.registry[0]], self.hosts))
        for malformed in ({}, ["not a table"], [{}]):
            with self.subTest(registry=malformed):
                self.assertTrue(quality.url_rule_check([], malformed, self.hosts))

    def test_mitm_globs_are_limited_to_hostname_syntax(self):
        for host in ("example.test", "*.example.test", "p*-ad-sign.byteimg.com", "p?-sign.douyinpic.com"):
            with self.subTest(host=host):
                self.assertEqual(quality.rewrite_check([], [host]), [])
        for host in ("*", "*.*", "EXAMPLE.test", "*.example..test", "https://example.test", "p[0-9].example.test",
                     "-bad.example.test", "bad-.example.test", "example.test\n", "example.test,other.test"):
            with self.subTest(host=host):
                self.assertTrue(quality.rewrite_check([], [host]))


class URLSourceValidationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cfg = self.root / "config"
        self.cfg.mkdir()
        self.dist = self.root / "dist"
        self.snapshot = self.root / "snapshots/test.gz"
        self.snapshot.parent.mkdir()
        self.old = b"DOMAIN,old.ads.test,REJECT\n"
        self.snapshot.write_bytes(gzip.compress(self.old))
        (self.cfg / "sources.toml").write_text('''
[meta]
stable_url = "https://update.test/stable"
latest_url = "https://update.test/latest"
min_total_rules = 1
[[sources]]
id = "test"
url = "https://source.test/rules"
parser = "surge_list"
min_rules = 1
max_deviation = 1.0
''')
        for filename in ("rewrite.toml", "whitelist.txt", "canary.txt"):
            (self.cfg / filename).write_text("")
        patches = patch.multiple(cli, ROOT=self.root, CFG=self.cfg, DIST=self.dist)
        patches.start()
        self.addCleanup(patches.stop)
        self.regex = r"^https://ads\.test/banner"
        self.download = f"URL-REGEX,{self.regex},REJECT\n".encode()

    def build(self, *args):
        with patch("adkit.fetch.http_get", return_value=self.download), contextlib.redirect_stdout(io.StringIO()):
            return cli.main(["build", *args])

    def register(self):
        (self.cfg / "url_rules.toml").write_text('''
[[url_rule]]
site = "test banner"
pattern = '^https://ads\\.test/banner'
example_urls = ["https://ads.test/banner"]
allow_urls = ["https://ads.test/product"]
''')

    def test_unregistered_candidate_falls_back_even_with_ignore_canary(self):
        self.assertEqual(self.build("--ignore-canary"), 0)
        self.assertEqual(gzip.decompress(self.snapshot.read_bytes()), self.old)
        self.assertNotIn("URL-REGEX", (self.dist / "latest/adkit.conf").read_text())
        self.assertIn("未登记", (self.dist / "stats.json").read_text())

    def test_missing_mitm_candidate_falls_back_to_valid_snapshot(self):
        self.register()
        self.assertEqual(self.build(), 0)
        self.assertEqual(gzip.decompress(self.snapshot.read_bytes()), self.old)
        self.assertIn("缺少 MITM", (self.dist / "stats.json").read_text())

    def test_unknown_source_without_valid_copy_prevents_output(self):
        self.snapshot.unlink()
        self.assertEqual(self.build("--ignore-canary"), 2)
        self.assertFalse(self.dist.exists())

    def test_user_url_rule_cannot_bypass_registry_with_ignore_canary(self):
        (self.cfg / "user_rules.txt").write_bytes(self.download)
        self.assertEqual(self.build("--offline", "--ignore-canary"), 2)
        self.assertFalse(self.dist.exists())

    def test_registered_rule_builds_with_explicit_mitm_host(self):
        self.register()
        (self.cfg / "rewrite.toml").write_text('[mitm]\nhosts = ["ads.test"]\n')
        self.assertEqual(self.build(), 0)
        self.assertEqual(gzip.decompress(self.snapshot.read_bytes()), self.download)
        output = (self.dist / "latest/adkit.conf").read_text()
        self.assertIn(f"URL-REGEX,{self.regex},REJECT", output)
        self.assertIn("hostname = ads.test", output)


if __name__ == "__main__":
    unittest.main()
