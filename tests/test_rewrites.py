import copy
import pathlib
import re
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

    def matching_rewrites(self, url):
        return [w["site"] for w in self.registry["rewrite"]
                if w.get("enabled", True) and re.search(w["pattern"], url)]

    def test_ad_query_parameters_can_be_reordered(self):
        cases = {
            "京东 广告弹窗/首页弹层": [
                "https://api.m.jd.com/client.action?functionId=homeAreaPop&client=apple",
                "https://api.m.jd.com/client.action?client=apple&functionId=homeAreaPop",
                "https://api.m.jd.com/client.action?client=apple&functionId=lite_advertising&version=1",
            ],
            "美团 开屏图接口/广告弹窗": [
                "https://www.meituan.com/api/v1/appstatus?ad=1&version=1",
                "https://www.meituan.com/api/v1/appstatus?version=1&ad=1",
                "https://www.meituan.com/api/v1/appstatus?version=1&ad=1&client=app",
                "https://www.meituan.com/api/v1/appstatus?ad=0",
                "https://www.meituan.com/api/v1/appstatus?version=1&ad=10",
                "https://www.meituan.com/api/v1/appstatus?version=1&ad=custom&client=app",
                "https://www.meituan.com/api/v1/appstatus?ad=",
                "https://www.meituan.com/api/v1/appstatus?ad",
                "https://www.meituan.com/api/v1/appstatus?version=1&ad&client=app",
            ],
        }
        for site, urls in cases.items():
            for url in urls:
                with self.subTest(url=url):
                    self.assertEqual(self.matching_rewrites(url), [site])

    def test_similar_parameters_and_values_are_not_ad_requests(self):
        urls = [
            "https://api.m.jd.com/client.action?notfunctionId=homeAreaPop",
            "https://api.m.jd.com/client.action?functionId=homeAreaPopExtra",
            "https://api.m.jd.com/client.action?functionId=lite_advertisingExtra",
            "https://api.m.jd.com/client.action?body=functionId%3DhomeAreaPop",
            "https://api.m.jd.com/client.action?functionId=wareBusiness&body=homeAreaPop",
            "https://www.meituan.com/api/v1/appstatus?notad=1",
            "https://www.meituan.com/api/v1/appstatus?address=1",
            "https://www.meituan.com/api/v1/appstatus?ad_extra=1",
            "https://www.meituan.com/api/v1/appstatus?body=version%3D1%26ad%3D1",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.matching_rewrites(url), [])

    def test_meituan_ad_images_with_cdn_variants(self):
        variants = [
            "banner.jpg?version=1",
            "banner-123.jpg",
            "banner-123.jpg@750w_1l",
            "banner.jpg@750w_1l_0e_1c_100q.jpg",
            "banner.jpg@750w_1l.webp?version=1",
            "banner.jpg.webp?version=1",
        ]
        for directory in ("adunion", "display", "midas", "bizad", "brandCpt"):
            for variant in variants:
                url = f"https://img.meituan.net/{directory}/{variant}"
                with self.subTest(url=url):
                    self.assertEqual(self.matching_rewrites(url), ["美团 广告素材图"])

    def test_meituan_cdn_variants_do_not_expand_to_product_images(self):
        urls = [
            "https://img.meituan.net/product/item-123.jpg@750w_1l?version=1",
            "https://img.meituan.net/adunion/banner.jpg.backup",
            "https://img.meituan.net/adunion/banner.jpg/normal.jpg",
            "https://img.meituan.net/adunion/banner.jpg@invalid",
            "https://img.meituan.net/adunion/banner.jpg@750w_1l.backup",
            "https://img.meituan.net/adunion/normal.txt?image=banner.jpg",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.matching_rewrites(url), [])


if __name__ == "__main__":
    unittest.main()
