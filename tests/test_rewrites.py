import copy
import pathlib
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from adkit import quality  # noqa: E402
from adkit.parsers import parse_surge_list  # noqa: E402


class RewriteRegistryTest(unittest.TestCase):
    def setUp(self):
        self.registry = tomllib.loads((ROOT / "config/rewrite.toml").read_text("utf8"))

    def test_registered_examples_and_https_hosts(self):
        self.assertEqual(quality.rewrite_check(self.registry["rewrite"], self.registry["mitm"]["hosts"]), [])

    def test_missing_host_rejects_real_registered_examples(self):
        hosts = [h for h in self.registry["mitm"]["hosts"] if h != "interface3.music.163.com"]
        self.assertTrue(any("interface3.music.163.com" in e
                            for e in quality.rewrite_check(self.registry["rewrite"], hosts)))

    def test_overbroad_video_regex_rejects_negative_example(self):
        registry = copy.deepcopy(self.registry)
        rewrite = next(w for w in registry["rewrite"] if w["site"] == "淘宝视频广告")
        rewrite["pattern"] = r"^https?://cloud\.video\.taobao\.com/vod/.*.mp4"
        errors = quality.rewrite_check(registry["rewrite"], registry["mitm"]["hosts"])
        self.assertTrue(any("负例被误匹配" in e and "nameXmp4" in e for e in errors))

    def test_remote_registered_rules_preserved_with_examples(self):
        expected = {"QQ 内嵌新闻流 开屏/热榜广告", "QQ 内嵌新闻流 广告拉取/上报",
                    "微信 小店/商品推荐位", "网易邮箱大师 广告配置拉取"}
        found = {w["site"] for w in self.registry["rewrite"] if w.get("enabled", True)
                 and w.get("example_urls") and w.get("allow_urls")}
        self.assertLessEqual(expected, found)
        google = next(w for w in self.registry["rewrite"] if w["site"] == "google.cn 跳转")
        self.assertIs(google["enabled"], False)

    def test_user_reported_weibo_host_preserved(self):
        rules, skipped = parse_surge_list((ROOT / "config/user_rules.txt").read_text("utf8"), "user")
        self.assertEqual(skipped, 0)
        self.assertTrue(any(r.pattern == "mediadata.api.weibo.com" and r.action == "REJECT" for r in rules))


if __name__ == "__main__":
    unittest.main()
