"""Validate build decisions and last-good state through the real CLI pipeline."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from adkit import cli, quality, render
from adkit.ir import Rule


class BuildTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cfg = self.root / "config"
        self.cfg.mkdir()
        self.dist = self.root / "dist"
        self.snapshot = self.root / "snapshots" / "test.gz"
        self.snapshot.parent.mkdir()
        self.old = b"DOMAIN,old.ads.test,REJECT\n"
        self.snapshot.write_bytes(gzip.compress(self.old))
        (self.cfg / "sources.toml").write_text('''
[meta]
stable_url = "https://example.test/stable"
latest_url = "https://example.test/latest"
min_total_rules = 1
[[sources]]
id = "test"
url = "https://source.test/rules"
parser = "surge_list"
min_rules = 1
max_deviation = 1.0
''')
        (self.cfg / "rewrite.toml").write_text("")
        (self.cfg / "whitelist.txt").write_text("")
        (self.cfg / "canary.txt").write_text("service.test\n")
        (self.cfg / "canary_urls.txt").write_text("https://service.test/me\n")
        self.patches = patch.multiple(cli, ROOT=self.root, CFG=self.cfg, DIST=self.dist)
        self.patches.start()
        self.addCleanup(self.patches.stop)

    def build(self, *args, download=b"DOMAIN,new.ads.test,REJECT\n"):
        with patch("adkit.fetch.http_get", return_value=download), contextlib.redirect_stdout(io.StringIO()):
            return cli.main(["build", *args])

    def test_live_success_saves_validated_input_and_all_channels(self):
        self.assertEqual(self.build(), 0)
        self.assertIn(b"new.ads.test", gzip.decompress(self.snapshot.read_bytes()))
        stats = json.loads((self.dist / "stats.json").read_text())
        self.assertTrue(stats["quality_passed"])
        self.assertIn("test", stats["input_sha256"])
        for channel in ("stable", "latest"):
            for suffix in ("conf", "module", "lite.module"):
                name = "adkit-lite.module" if suffix == "lite.module" else f"adkit.{suffix}"
                self.assertTrue((self.dist / channel / name).exists())

    def test_bad_source_uses_last_good_snapshot(self):
        self.assertEqual(self.build(download=b"DOMAIN,service.test,REJECT\n"), 0)
        self.assertEqual(gzip.decompress(self.snapshot.read_bytes()), self.old)
        stats = json.loads((self.dist / "stats.json").read_text())
        self.assertTrue(any("金丝雀" in warning for warning in stats["warnings"]))
        self.assertNotIn("DOMAIN,service.test,REJECT", (self.dist / "stable/adkit.conf").read_text())

    def test_global_url_failure_does_not_commit_candidate(self):
        original = self.snapshot.read_bytes()
        (self.cfg / "rewrite.toml").write_text('''
[[rewrite]]
site = "bad change"
pattern = '^https://service\\.test/me$'
target = "_"
action = "REJECT-DICT"
example_urls = ["https://service.test/me"]
allow_urls = ["https://service.test/profile"]
[mitm]
hosts = ["service.test"]
''')
        self.assertEqual(self.build(), 2)
        self.assertEqual(self.snapshot.read_bytes(), original)
        self.assertFalse((self.root / "cache").exists())
        self.assertFalse((self.dist / "stats.json").exists())

    def test_ignore_canary_marks_output_unpublishable_and_keeps_snapshot(self):
        original = self.snapshot.read_bytes()
        self.assertEqual(self.build("--ignore-canary", download=b"DOMAIN,service.test,REJECT\n"), 0)
        self.assertFalse(json.loads((self.dist / "stats.json").read_text())["quality_passed"])
        self.assertEqual(self.snapshot.read_bytes(), original)

    def test_user_direct_can_override_source_for_canary(self):
        (self.cfg / "user_rules.txt").write_text("DOMAIN-SUFFIX,service.test,DIRECT\n")
        self.assertEqual(self.build(download=b"DOMAIN,service.test,REJECT\n"), 0)
        output = (self.dist / "stable/adkit.conf").read_text()
        self.assertLess(output.index("DOMAIN-SUFFIX,service.test,DIRECT"), output.index("DOMAIN,service.test,REJECT"))

    def test_missing_source_prevents_output(self):
        self.snapshot.unlink()
        self.assertEqual(self.build(download=b"<html>error</html>"), 2)
        self.assertFalse(self.dist.exists())

    def test_offline_build_does_not_rewrite_input(self):
        original = self.snapshot.read_bytes()
        self.assertEqual(self.build("--offline"), 0)
        self.assertEqual(self.snapshot.read_bytes(), original)
        self.assertFalse((self.root / "cache").exists())

    def test_invalid_manual_rule_is_reported(self):
        (self.cfg / "user_rules.txt").write_text("IP-CIDR,1.2.3.0/24,PROXY\n")
        self.assertEqual(self.build(), 2)
        self.assertFalse(self.dist.exists())

    def test_explicit_user_ip_reject_is_retained(self):
        (self.cfg / "user_rules.txt").write_text("IP-CIDR,203.0.113.0/24,REJECT\n")
        self.assertEqual(self.build(), 0)
        self.assertIn("IP-CIDR,203.0.113.0/24,REJECT,no-resolve", (self.dist / "stable/adkit.conf").read_text())

    def test_upstream_ip_reject_is_screened(self):
        self.assertEqual(self.build(download=b"DOMAIN,new.ads.test,REJECT\nIP-CIDR,203.0.113.0/24,REJECT\n"), 0)
        self.assertNotIn("IP-CIDR,203.0.113.0/24,REJECT", (self.dist / "stable/adkit.conf").read_text())


class MatchingAndMobileTest(unittest.TestCase):
    def test_canary_obeys_rendered_whitelist_order(self):
        rules = [Rule("DOMAIN-SUFFIX", "qq.com", "REJECT", ["source"]),
                 Rule("DOMAIN-SUFFIX", "qq.com", "DIRECT", ["whitelist"])]
        self.assertEqual(quality.canary_check(rules, ["qq.com"]), [])

    def test_upstream_direct_does_not_override_reject(self):
        rules = [Rule("DOMAIN-SUFFIX", "qq.com", "DIRECT", ["source"]),
                 Rule("DOMAIN-SUFFIX", "qq.com", "REJECT", ["source"])]
        self.assertEqual(len(quality.canary_check(rules, ["qq.com"])), 1)

    def test_url_canary_checks_regex(self):
        rules = [Rule("URL-REGEX", r"^https://qq\.com/", "REJECT", ["source"])]
        self.assertTrue(quality.url_canary_check(rules, [], ["https://qq.com/me"]))

    def test_generated_config_enables_rewrites_and_mitm(self):
        output = render.render_full_conf([], [], ["example.test"], "https://update.test", "# test")
        self.assertIn("always-reject-url-rewrite = true", output)
        self.assertIn("[MITM]\nenable = true\nhostname = example.test", output)
        quality.scrub_assert(output)

    def test_modules_merge_hostnames_without_replacing_nodes(self):
        for output in (render.render_module([], [], ["example.test"], "# test"),
                       render.render_lite_module([], ["example.test"], "# test")):
            self.assertIn("hostname = %APPEND% example.test", output)
            self.assertIn("enable = true", output)
            self.assertNotIn("[Proxy]", output)
            self.assertNotIn("update-url", output)
            quality.scrub_assert(output)


if __name__ == "__main__":
    unittest.main()
