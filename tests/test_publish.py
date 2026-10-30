"""Exercise the real publication commands against local bare Git repositories."""
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("adkit_publish", Path(__file__).resolve().parents[1] / "scripts/publish.py")
publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish)


class PublishTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="adkit-publish-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.remote = Path(self.temp.name) / "remote.git"
        self.root.mkdir()
        subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(self.remote)], check=True, capture_output=True)
        subprocess.run(["git", "init", "--initial-branch=main", str(self.root)], check=True, capture_output=True)
        publish.git(self.root, "config", "user.name", "test")
        publish.git(self.root, "config", "user.email", "test@example.invalid")
        (self.root / "source-only.py").write_text("# must never be published\n")
        publish.git(self.root, "add", "source-only.py")
        publish.git(self.root, "commit", "-m", "source")
        publish.git(self.root, "remote", "add", "origin", str(self.remote))
        publish.git(self.root, "push", "origin", "main")

    def build(self, version):
        for name, text in {
            "dist/stable/adkit.conf": f"stable-{version}\nupdate-url = stable\n",
            "dist/latest/adkit.conf": f"latest-{version}\nupdate-url = latest\n",
            "dist/stable/adkit.module": f"stable-module-{version}\nupdate-url = stable-module\n",
            "dist/latest/adkit.module": f"latest-module-{version}\nupdate-url = latest-module\n",
            "dist/stable/adkit-lite.module": f"stable-lite-{version}\nupdate-url = stable-lite\n",
            "dist/latest/adkit-lite.module": f"latest-lite-{version}\nupdate-url = latest-lite\n",
            "dist/adkit-adonly.conf": f"rules-{version}\n",
            "dist/stats.json": json.dumps({"version": version}),
        }.items():
            publish.write_file(self.root, name, text.encode())
        publish.write_file(self.root, "snapshots/example.gz", gzip.compress(f"snapshot-{version}".encode()))

    def bootstrap(self):
        self.assertIsNone(publish.restore(self.root))
        self.build("one")
        return publish.publish(self.root)

    def remote_file(self, name):
        return publish.git(self.remote, "show", f"dist:{name}").stdout

    def test_bootstrap_contains_only_artifacts_and_snapshots(self):
        self.bootstrap()
        paths = publish.git(self.remote, "ls-tree", "-r", "--name-only", "dist").stdout.decode().splitlines()
        self.assertEqual(set(paths), {*publish.ARTIFACTS, "snapshots/example.gz"})
        self.assertIn(b"stable-one", self.remote_file("stable/adkit.conf"))
        self.assertIn(b"update-url = stable", self.remote_file("pending-stable.conf"))
        self.assertIn(b"update-url = stable-module", self.remote_file("pending-stable.module"))
        self.assertIn(b"update-url = stable-lite", self.remote_file("pending-stable-lite.module"))
        self.assertEqual(publish.git(self.root, "branch", "--show-current").stdout.strip(), b"main")
        self.assertTrue((self.root / "source-only.py").exists())

    def test_daily_preserves_stable_and_weekly_promotes_pending(self):
        self.bootstrap()
        old = {name: self.remote_file(f"stable/{name}") for name, _ in publish.CHANNEL_FILES}
        publish.restore(self.root)
        self.build("two")
        publish.publish(self.root)
        for name, _ in publish.CHANNEL_FILES:
            self.assertEqual(self.remote_file(f"stable/{name}"), old[name])
        self.assertIn(b"latest-two", self.remote_file("latest/adkit.conf"))
        self.assertIn(b"stable-two", self.remote_file("pending-stable.conf"))
        self.assertIn(b"latest-module-two", self.remote_file("latest/adkit.module"))
        self.assertIn(b"latest-lite-two", self.remote_file("latest/adkit-lite.module"))
        self.assertIn(b"stable-module-two", self.remote_file("pending-stable.module"))
        self.assertIn(b"stable-lite-two", self.remote_file("pending-stable-lite.module"))
        output = Path(self.temp.name) / "release"
        commit = publish.promote(self.root, output)
        self.assertIn(b"stable-two", self.remote_file("stable/adkit.conf"))
        self.assertIn(b"update-url = stable", (output / "stable/adkit.conf").read_bytes())
        self.assertIn(b"stable-module-two", self.remote_file("stable/adkit.module"))
        self.assertIn(b"stable-lite-two", self.remote_file("stable/adkit-lite.module"))
        for name, _ in publish.CHANNEL_FILES:
            self.assertEqual((output / "stable" / name).read_bytes(), self.remote_file(f"stable/{name}"))
        self.assertEqual((output / "stats.json").read_bytes(), self.remote_file("stats.json"))
        # No new content means rerunning promotion uses the same immutable tag SHA.
        self.assertEqual(publish.promote(self.root, output), commit)

    def test_restore_loads_previous_stats_and_validated_snapshots(self):
        original = self.bootstrap()
        (self.root / "dist/stats.json").write_text("{}")
        (self.root / "snapshots/example.gz").write_bytes(b"local stale bytes")
        self.assertEqual(publish.restore(self.root), original)
        self.assertEqual(json.loads((self.root / "dist/stats.json").read_text()), {"version": "one"})
        self.assertEqual(gzip.decompress((self.root / "snapshots/example.gz").read_bytes()), b"snapshot-one")

    def test_conf_only_migration_bootstraps_modules_without_advancing_conf(self):
        base = self.bootstrap()
        with publish.isolated_tree(self.root, base) as tree:
            for path in tree.rglob("*.module"):
                path.unlink()
            publish.push_tree(self.root, tree, base, "legacy conf-only dist")
        old_conf = self.remote_file("stable/adkit.conf")
        publish.restore(self.root)
        self.build("two")
        publish.publish(self.root)
        self.assertEqual(self.remote_file("stable/adkit.conf"), old_conf)
        self.assertIn(b"stable-module-two", self.remote_file("stable/adkit.module"))
        self.assertIn(b"stable-lite-two", self.remote_file("stable/adkit-lite.module"))
        self.assertIn(b"stable-two", self.remote_file("pending-stable.conf"))

    def test_missing_single_stable_module_preserves_other_formats(self):
        base = self.bootstrap()
        with publish.isolated_tree(self.root, base) as tree:
            (tree / "stable/adkit-lite.module").unlink()
            publish.push_tree(self.root, tree, base, "add lite support later")
        old_conf = self.remote_file("stable/adkit.conf")
        old_module = self.remote_file("stable/adkit.module")
        publish.restore(self.root)
        self.build("two")
        publish.publish(self.root)
        self.assertEqual(self.remote_file("stable/adkit.conf"), old_conf)
        self.assertEqual(self.remote_file("stable/adkit.module"), old_module)
        self.assertIn(b"stable-lite-two", self.remote_file("stable/adkit-lite.module"))

    def test_explicit_failed_quality_gate_rejects_publish(self):
        original = self.bootstrap()
        publish.restore(self.root)
        self.build("two")
        publish.write_file(self.root, "dist/stats.json", b'{"quality_passed": false}\n')
        with self.assertRaisesRegex(ValueError, "质量检查"):
            publish.publish(self.root)
        self.assertEqual(publish.git(self.remote, "rev-parse", "dist").stdout.decode().strip(), original)
        self.assertIn(b"latest-one", self.remote_file("latest/adkit.conf"))
        # Successful current builds and historical stats without the field both work.
        publish.write_file(self.root, "dist/stats.json", b'{"quality_passed": true}\n')
        publish.publish(self.root)
        self.assertIn(b"latest-two", self.remote_file("latest/adkit.conf"))

    def test_explicit_failed_quality_gate_rejects_promotion(self):
        base = self.bootstrap()
        with publish.isolated_tree(self.root, base) as tree:
            publish.write_file(tree, "stats.json", b'{"quality_passed": false}\n')
            invalid = publish.push_tree(self.root, tree, base, "invalid quality preview")
        with self.assertRaisesRegex(ValueError, "质量检查"):
            publish.promote(self.root, Path(self.temp.name) / "release")
        self.assertEqual(publish.git(self.remote, "rev-parse", "dist").stdout.decode().strip(), invalid)

    def test_incomplete_pending_formats_do_not_partially_promote(self):
        self.bootstrap()
        publish.restore(self.root)
        self.build("two")
        base = publish.publish(self.root)
        with publish.isolated_tree(self.root, base) as tree:
            (tree / "pending-stable-lite.module").unlink()
            broken = publish.push_tree(self.root, tree, base, "incomplete pending")
        with self.assertRaises(subprocess.CalledProcessError):
            publish.promote(self.root, Path(self.temp.name) / "release")
        self.assertEqual(publish.git(self.remote, "rev-parse", "dist").stdout.decode().strip(), broken)
        self.assertIn(b"stable-one", self.remote_file("stable/adkit.conf"))
        self.assertIn(b"stable-module-one", self.remote_file("stable/adkit.module"))

    def test_unreachable_remote_aborts_instead_of_bootstrap(self):
        publish.git(self.root, "remote", "set-url", "origin", str(Path(self.temp.name) / "missing.git"))
        with self.assertRaises(subprocess.CalledProcessError):
            publish.restore(self.root)
        self.assertFalse(publish.state_path(self.root).exists())

    def test_fetch_failure_clears_previously_saved_state(self):
        self.bootstrap()
        publish.restore(self.root)
        real_git = publish.git

        def fail_fetch(root, *args, **kwargs):
            if args[0] == "fetch":
                raise subprocess.CalledProcessError(128, ["git", "fetch"], stderr=b"temporary failure")
            return real_git(root, *args, **kwargs)

        with patch.object(publish, "git", side_effect=fail_fetch):
            with self.assertRaises(subprocess.CalledProcessError):
                publish.restore(self.root)
        self.assertFalse(publish.state_path(self.root).exists())

    def test_existing_dist_without_stable_is_not_bootstrap(self):
        base = self.bootstrap()
        with publish.isolated_tree(self.root, base) as tree:
            (tree / "stable/adkit.conf").unlink()
            publish.push_tree(self.root, tree, base, "broken stable")
        with self.assertRaises(subprocess.CalledProcessError):
            publish.restore(self.root)
        self.assertFalse(publish.state_path(self.root).exists())

    def test_concurrent_promotion_cannot_be_overwritten_by_daily(self):
        self.bootstrap()
        publish.restore(self.root)
        self.build("two")
        publish.publish(self.root)
        # Daily reads stable-one, then weekly promotes stable-two before daily pushes.
        publish.restore(self.root)
        self.build("three")
        promoted = publish.promote(self.root, Path(self.temp.name) / "release")
        with self.assertRaises(subprocess.CalledProcessError):
            publish.publish(self.root)
        self.assertEqual(publish.git(self.remote, "rev-parse", "dist").stdout.decode().strip(), promoted)
        self.assertIn(b"stable-two", self.remote_file("stable/adkit.conf"))
        self.assertIn(b"latest-two", self.remote_file("latest/adkit.conf"))

    def test_publish_requires_restore_and_nonempty_artifacts(self):
        self.build("one")
        with self.assertRaises(ValueError):
            publish.publish(self.root)
        publish.restore(self.root)
        (self.root / "dist/latest/adkit.conf").write_bytes(b"")
        with self.assertRaises(ValueError):
            publish.publish(self.root)
        self.assertIsNone(publish.fetch_dist(self.root))

    def test_concurrent_bootstrap_cannot_replace_new_dist_branch(self):
        # Both writers observed the branch as absent. Only the first may create it.
        self.assertIsNone(publish.restore(self.root))
        self.build("one")
        with publish.isolated_tree(self.root, None) as tree:
            publish.write_file(tree, "stable/adkit.conf", b"other publisher\n")
            winner = publish.push_tree(self.root, tree, None, "concurrent bootstrap")
        with self.assertRaises(subprocess.CalledProcessError):
            publish.publish(self.root)
        self.assertEqual(self.remote_file("stable/adkit.conf"), b"other publisher\n")
        self.assertEqual(publish.git(self.remote, "rev-parse", "dist").stdout.decode().strip(), winner)

    def test_invalid_previous_stats_aborts_restore_and_clears_state(self):
        base = self.bootstrap()
        publish.restore(self.root)
        with publish.isolated_tree(self.root, base) as tree:
            publish.write_file(tree, "stats.json", b"not JSON\n")
            publish.push_tree(self.root, tree, base, "broken stats")
        with self.assertRaises(ValueError):
            publish.restore(self.root)
        self.assertFalse(publish.state_path(self.root).exists())

    def test_legacy_source_files_are_removed_from_dist(self):
        base = self.bootstrap()
        with publish.isolated_tree(self.root, base) as tree:
            (tree / "legacy-source.py").write_text("# old publishing bug\n")
            publish.push_tree(self.root, tree, base, "legacy artifact")
        publish.restore(self.root)
        self.build("two")
        publish.publish(self.root)
        files = publish.git(self.remote, "ls-tree", "-r", "--name-only", "dist").stdout
        self.assertNotIn(b"legacy-source.py", files)


if __name__ == "__main__":
    unittest.main()
