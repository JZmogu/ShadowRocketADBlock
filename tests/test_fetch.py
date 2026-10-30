import contextlib
import gzip
import http.client
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from adkit import fetch


class Response:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


def partial(first, final, total, body, etag='"v1"'):
    headers = {"Content-Range": f"bytes {first}-{final}/{total}"}
    if etag:
        headers["ETag"] = etag
    return Response(206, body, headers)


class DownloadTest(unittest.TestCase):
    def download(self, responses, **kwargs):
        with patch.object(fetch.urllib.request, "urlopen", side_effect=responses) as request:
            with patch.object(fetch.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
                data = fetch.http_get("https://example.test/rules", **kwargs)
        return data, request.call_args_list

    def test_full_response_replaces_downloaded_prefix(self):
        data, requests = self.download(
            [partial(0, 2, 6, b"abc"), Response(200, b"abcdef")], chunk=3,
        )
        self.assertEqual(data, b"abcdef")
        self.assertEqual(requests[1].args[0].get_header("If-range"), '"v1"')

    def test_unchanged_etag_allows_contiguous_ranges(self):
        data, requests = self.download(
            [partial(0, 2, 6, b"abc"), partial(3, 5, 6, b"def")], chunk=3,
        )
        self.assertEqual(data, b"abcdef")
        self.assertEqual(requests[1].args[0].get_header("Range"), "bytes=3-5")

    def test_without_validator_restart_as_full_download(self):
        data, requests = self.download(
            [partial(0, 2, 6, b"old", etag=None), Response(200, b"newest")], chunk=3,
        )
        self.assertEqual(data, b"newest")
        self.assertIsNone(requests[1].args[0].get_header("Range"))

    def test_changed_etag_discards_prefix(self):
        data, requests = self.download(
            [partial(0, 2, 6, b"old"), partial(3, 5, 6, b"bad", etag='"v2"'),
             Response(200, b"newest")],
            chunk=3, tries=2,
        )
        self.assertEqual(data, b"newest")
        self.assertIsNone(requests[2].args[0].get_header("Range"))

    def test_inconsistent_ranges_are_rejected(self):
        for response in [
            partial(1, 3, 6, b"bcd"),
            partial(0, 3, 6, b"abcd"),
            partial(0, 2, 6, b"ab"),
            Response(206, b"abc", {"ETag": '"v1"'}),
            Response(200, b"abc", {"Content-Length": "4"}),
        ]:
            with self.subTest(headers=response.headers), self.assertRaises(RuntimeError):
                self.download([response], chunk=3, tries=1)

    def test_partial_body_is_not_appended(self):
        data, _ = self.download(
            [partial(0, 2, 6, b"abc"),
             Response(200, http.client.IncompleteRead(b"broken", 6)),
             Response(200, b"newest")],
            chunk=3, tries=2,
        )
        self.assertEqual(data, b"newest")

    def test_valid_download_is_not_limited_to_four_times_retry_count(self):
        data, requests = self.download(
            [partial(i, i, 6, bytes([97 + i])) for i in range(6)],
            chunk=1, tries=1,
        )
        self.assertEqual(data, b"abcdef")
        self.assertEqual(len(requests), 6)


class SourcesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.cache = self.root / "cache"
        self.snapshots = self.root / "snapshots"
        self.source = {"id": "one", "parser": "surge_list", "url": "https://example.test/rules"}
        self.cfg = {"sources": [self.source]}

    @staticmethod
    def rules(count):
        return "".join(f"DOMAIN-SUFFIX,ad{i}.example.com,REJECT\n" for i in range(count)).encode()

    def save_snapshot(self, data):
        self.snapshots.mkdir(exist_ok=True)
        path = self.snapshots / "one.gz"
        path.write_bytes(gzip.compress(data, mtime=0))
        return path

    def load(self, **kwargs):
        return fetch.load_sources(self.cfg, self.cache, self.snapshots, **kwargs)

    def test_error_page_cannot_overwrite_good_snapshot(self):
        good = self.rules(10)
        path = self.save_snapshot(good)
        original = path.read_bytes()
        pending = {}
        with patch.object(fetch, "http_get", return_value=b"<html>maintenance</html>"):
            result = self.load(pending=pending)
        self.assertEqual(result[0][1], good.decode())
        self.assertIn("回退", result[0][2])
        self.assertEqual(pending, {"one": good})
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(self.cache.exists())
        with patch.object(fetch, "http_get", side_effect=RuntimeError("offline")):
            self.assertEqual(self.load()[0][1], good.decode())

    def test_rule_count_drop_or_growth_uses_last_good(self):
        good = self.rules(10)
        self.save_snapshot(good)
        for count in [1, 20]:
            with self.subTest(count=count), patch.object(fetch, "http_get", return_value=self.rules(count)):
                result = self.load()
            self.assertEqual(result[0][1], good.decode())
            self.assertIn("偏移超过", result[0][2])

    def test_valid_candidate_is_saved_only_after_explicit_commit(self):
        good = self.rules(10)
        path = self.save_snapshot(good)
        original = path.read_bytes()
        updated = self.rules(11)
        pending = {}
        with patch.object(fetch, "http_get", return_value=updated):
            self.assertEqual(self.load(pending=pending)[0][1], updated.decode())
        # A later CLI quality failure can return here without changing either copy.
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(self.cache.exists())
        fetch.commit_sources(pending, self.cache, self.snapshots)
        self.assertEqual(gzip.decompress(path.read_bytes()), updated)
        self.assertEqual((self.cache / "one.txt").read_bytes(), updated)

    def test_secondary_url_is_used_after_bad_content(self):
        self.source["fallback_urls"] = ["https://backup.test/rules"]
        good = self.rules(10)
        with patch.object(fetch, "http_get", side_effect=[b"<html>error</html>", good]) as get:
            result = self.load()
        self.assertEqual(get.call_count, 2)
        self.assertEqual(result[0][1], good.decode())
        self.assertIn("有效规则仅 0", result[0][2])

    def test_validator_failure_falls_back_without_replacing_snapshot(self):
        good = self.rules(10)
        path = self.save_snapshot(good)
        bad = good + b"DOMAIN-SUFFIX,qq.com,REJECT\n"

        def validate(source, text):
            self.assertEqual(source["id"], "one")
            if "qq.com" in text:
                raise ValueError("canary rejected")

        with patch.object(fetch, "http_get", return_value=bad):
            result = self.load(validate=validate)
        self.assertEqual(result[0][1], good.decode())
        self.assertIn("canary rejected", result[0][2])
        self.assertEqual(gzip.decompress(path.read_bytes()), good)

    def test_invalid_local_content_is_not_accepted_as_fallback(self):
        self.save_snapshot(b"<html>bad snapshot</html>")
        with patch.object(fetch, "http_get", side_effect=RuntimeError("offline")):
            result = self.load()
        self.assertIsNone(result[0][1])
        self.assertIn("snapshot 无效", result[0][2])

    def test_configured_minimum_applies_without_history(self):
        self.source["min_rules"] = 5
        with patch.object(fetch, "http_get", return_value=self.rules(4)):
            self.assertIsNone(self.load()[0][1])

    def test_snapshot_repairs_bad_cache_only_after_commit(self):
        good = self.rules(10)
        self.save_snapshot(good)
        self.cache.mkdir()
        cached = self.cache / "one.txt"
        cached.write_text("<html>bad cache</html>")
        pending = {}
        self.assertEqual(self.load(live=False, pending=pending)[0][1], good.decode())
        self.assertEqual(cached.read_text(), "<html>bad cache</html>")
        fetch.commit_sources(pending, self.cache, self.snapshots)
        self.assertEqual(cached.read_bytes(), good)

    def test_corrupt_gzip_can_fall_back_to_valid_cache(self):
        path = self.save_snapshot(self.rules(1))
        path.write_bytes(b"not a gzip file")
        self.cache.mkdir()
        good = self.rules(10)
        (self.cache / "one.txt").write_bytes(good)
        result = self.load(live=False)
        self.assertEqual(result[0][1], good.decode())
        self.assertIn("snapshot 无效", result[0][2])

    def test_corrupt_deflate_body_can_fall_back_to_valid_cache(self):
        path = self.save_snapshot(self.rules(1))
        damaged = bytearray(path.read_bytes())
        damaged[10] = 255  # Valid gzip header, invalid DEFLATE body.
        path.write_bytes(damaged)
        self.cache.mkdir()
        good = self.rules(10)
        (self.cache / "one.txt").write_bytes(good)
        result = self.load(live=False)
        self.assertEqual(result[0][1], good.decode())
        self.assertIn("snapshot 无效", result[0][2])

    def test_offline_read_does_not_create_directories(self):
        with patch.object(fetch, "http_get") as get:
            self.assertIsNone(self.load(live=False)[0][1])
        get.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
