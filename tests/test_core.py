import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from adkit import merge, quality, render  # noqa: E402
from adkit.ir import Rule  # noqa: E402
from adkit.parsers import parse_sr_conf_rule, parse_surge_list  # noqa: E402


class ParseTest(unittest.TestCase):
    def test_surge_basic(self):
        rules, sk = parse_surge_list("DOMAIN-SUFFIX,Ads.Example.COM,REJECT\n# c\n垃圾行\n", "t")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].pattern, "ads.example.com")
        self.assertEqual(sk, 1)

    def test_surge_no_action_defaults_reject(self):
        rules, _ = parse_surge_list("DOMAIN-SUFFIX,x.com", "t")
        self.assertEqual(rules[0].action, "REJECT")

    def test_unknown_policy_skipped(self):
        rules, sk = parse_surge_list("DOMAIN-SUFFIX,x.com,节点选择", "t")
        self.assertEqual((rules, sk), ([], 1))

    def test_single_label_suffix_demoted_to_domain(self):
        rules, _ = parse_surge_list("DOMAIN-SUFFIX,localhost,REJECT", "t")
        self.assertEqual(rules[0].type, "DOMAIN")

    def test_sr_conf_section_extract(self):
        conf = "[General]\nupdate-url = http://x\n[Rule]\nDOMAIN-SUFFIX,a.com,Reject\nDOMAIN-SUFFIX,b.com,REJECT-DICT\n[MITM]\nca-p12 = SECRET\n"
        rules, _ = parse_sr_conf_rule(conf, "t")
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[1].action, "REJECT-DICT")

    def test_sr_pure_rulefile(self):
        rules, _ = parse_sr_conf_rule("// comment\nDOMAIN-SUFFIX,a.com,REJECT\nFINAL", "t")
        self.assertEqual(len(rules), 1)

    def test_ip_cidr_noresolve(self):
        rules, _ = parse_surge_list("IP-CIDR,1.2.3.0/24,REJECT,no-resolve", "t")
        self.assertEqual(rules[0].type, "IP-CIDR")
        self.assertEqual(rules[0].action, "REJECT")


class MergeTest(unittest.TestCase):
    def test_dedup_merges_sources(self):
        a = [Rule("DOMAIN-SUFFIX", "x.com", "REJECT", ["s1"]), Rule("DOMAIN-SUFFIX", "x.com", "REJECT", ["s2"])]
        out = merge.dedup(a)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].sources, ["s1", "s2"])

    def test_absorb_child_into_parent(self):
        rs = [
            Rule("DOMAIN-SUFFIX", "x.com", "REJECT", ["s"]),
            Rule("DOMAIN-SUFFIX", "a.x.com", "REJECT", ["s"]),
            Rule("DOMAIN-SUFFIX", "a.x.com", "REJECT-200", ["s"]),  # 动作不同：不吸收
            Rule("DOMAIN", "b.x.com", "REJECT", ["s"]),  # 子域精确：吸收
        ]
        out, dropped = merge.absorb(rs)
        kept = {(r.type, r.pattern) for r in out}
        self.assertEqual(kept, {("DOMAIN-SUFFIX", "x.com"), ("DOMAIN-SUFFIX", "a.x.com")})
        self.assertEqual(dropped, 2)

    def test_parent_before_child_lexorder(self):
        rs = [Rule("DOMAIN-SUFFIX", "ab.b.com", "REJECT", ["s"]), Rule("DOMAIN-SUFFIX", "b.com", "REJECT", ["s"])]
        out, dropped = merge.absorb(rs)
        self.assertEqual([(r.pattern) for r in out], ["b.com"])
        self.assertEqual(dropped, 1)


class QualityTest(unittest.TestCase):
    def test_canary_violation(self):
        rs = [Rule("DOMAIN-SUFFIX", "qq.com", "REJECT", ["evil"]), Rule("DOMAIN-SUFFIX", "weibo.cn", "DIRECT", ["wl"])]
        bad = quality.canary_check(rs, ["qq.com", "weibo.cn"])
        self.assertEqual([d for d, _ in bad], ["qq.com"])

    def test_scrub_ca(self):
        with self.assertRaises(AssertionError):
            quality.scrub_assert("x\nCA-P12 = abc\n")

    def test_deviation(self):
        w = quality.count_deviation({"per_source": {"a": 1000}}, {"per_source": {"a": 400}})
        self.assertEqual(len(w), 1)


class RenderTest(unittest.TestCase):
    def test_whitelist_first_and_no_ca(self):
        rs = [
            Rule("DOMAIN", "ad.com", "REJECT", ["s"]),
            Rule("DOMAIN-SUFFIX", "keep.com", "DIRECT", ["whitelist"]),
            Rule("DOMAIN-SUFFIX", "z.com", "REJECT-200", ["s"]),
            Rule("DOMAIN-SUFFIX", "app.cn", "DIRECT", ["upstream"]),
        ]
        out = render.render_full_conf(rs, [{"pattern": "p", "target": "_", "action": "REJECT-DICT"}], ["*.a.com"], "http://u", "# hdr")
        rule_part = out.split("[Rule]")[1].split("[URL Rewrite]")[0]
        # 用户白名单第一；上游 DIRECT 垫底；REJECT 主区居中（精确拦截优先于宽泛放行）
        self.assertLess(rule_part.index("keep.com"), rule_part.index("ad.com"))
        self.assertLess(rule_part.index("z.com"), rule_part.index("app.cn"))
        self.assertIn("[MITM]", out)
        self.assertIn("hostname = *.a.com", out)
        quality.scrub_assert(out)

    def test_adonly_has_no_general_no_mitm(self):
        out = render.render_adonly([Rule("DOMAIN-SUFFIX", "z.com", "REJECT", ["s"])], "# h")
        self.assertTrue(out.split("\n")[0].startswith("#"))
        self.assertNotIn("[General]", out)
        self.assertNotIn("[MITM]", out)

    def test_module_three_sections_no_general(self):
        rs = [
            Rule("DOMAIN", "ad.com", "REJECT", ["s"]),
            Rule("DOMAIN-SUFFIX", "app.cn", "DIRECT", ["upstream"]),
        ]
        out = render.render_module(rs, [{"pattern": "^https?://x", "target": "_", "action": "REJECT-DICT"}], ["*.a.com", "b.com"], "# hdr")
        self.assertIn("#!name=", out)                      # SR 模块头
        self.assertIn("[Rule]", out)
        self.assertIn("[URL Rewrite]", out)
        self.assertIn("hostname = %APPEND% *.a.com,b.com", out)  # 模块必须 %APPEND%，防互相覆盖
        self.assertNotIn("[General]", out)                 # 模块绝不带 General/update-url
        self.assertNotIn("update-url", out)
        quality.scrub_assert(out)

    def test_lite_module_no_rules_section(self):
        out = render.render_lite_module([{"pattern": "^https?://x", "target": "_", "action": "REJECT-DICT"}], ["*.a.com"], "# hdr")
        self.assertNotIn("[Rule]", out)                    # 拆分版：大规则走规则页，模块只带 rewrite+MITM
        self.assertIn("[URL Rewrite]", out)
        self.assertIn("hostname = %APPEND% *.a.com", out)
        quality.scrub_assert(out)


if __name__ == "__main__":
    unittest.main()
