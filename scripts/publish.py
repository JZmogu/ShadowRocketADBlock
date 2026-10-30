#!/usr/bin/env python3
"""Restore validated build state and publish isolated dist commits.

The source checkout is never switched to dist. A remote read failure aborts the
operation; only ls-remote's explicit "no matching ref" result permits bootstrap.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DIST_REF = "refs/heads/dist"
TRACKING_REF = "refs/remotes/origin/dist"
IDENTITY = ["-c", "user.name=adkit-bot", "-c", "user.email=adkit-bot@users.noreply.github.com"]
CHANNEL_FILES = (
    ("adkit.conf", "pending-stable.conf"),
    ("adkit.module", "pending-stable.module"),
    ("adkit-lite.module", "pending-stable-lite.module"),
)
ARTIFACTS = tuple(
    path for name, pending in CHANNEL_FILES
    for path in (f"stable/{name}", f"latest/{name}", pending)
) + ("adkit-adonly.conf", "stats.json")


def git(root: Path, *args: str, check: bool = True, data: bytes | None = None):
    return subprocess.run(
        ["git", "-C", str(root), *args], input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=check,
    )


def fetch_dist(root: Path) -> str | None:
    result = git(root, "ls-remote", "--exit-code", "--heads", "origin", DIST_REF, check=False)
    if result.returncode == 2:
        return None
    result.check_returncode()
    git(root, "fetch", "--no-tags", "origin", f"+{DIST_REF}:{TRACKING_REF}")
    return git(root, "rev-parse", TRACKING_REF).stdout.decode().strip()


def state_path(root: Path) -> Path:
    path = Path(git(root, "rev-parse", "--git-path", "adkit-dist-state.json").stdout.decode().strip())
    return path if path.is_absolute() else root / path


def read_blob(root: Path, commit: str, name: str) -> bytes:
    data = git(root, "show", f"{commit}:{name}").stdout
    if not data:
        raise ValueError(f"dist 中的 {name} 为空，停止发布")
    return data


def read_optional_blob(root: Path, commit: str, name: str) -> bytes | None:
    """Only an explicitly absent path permits bootstrapping a newly added format."""
    names = git(root, "ls-tree", "--name-only", commit, "--", name).stdout.decode().splitlines()
    return read_blob(root, commit, name) if name in names else None


def checked_stats(data: bytes) -> dict:
    stats = json.loads(data)
    if not isinstance(stats, dict):
        raise ValueError("stats.json 必须为 JSON 对象，停止发布")
    if stats.get("quality_passed") is False:
        raise ValueError("构建未通过质量检查，停止发布")
    return stats


def restore(root: Path) -> str | None:
    marker = state_path(root)
    marker.unlink(missing_ok=True)
    base = fetch_dist(root)
    if base is not None:
        # An existing branch must have an intact stable; it is not bootstrap.
        read_blob(root, base, "stable/adkit.conf")
        stats = read_blob(root, base, "stats.json")
        json.loads(stats)
        paths = git(root, "ls-tree", "-r", "--name-only", base, "--", "snapshots").stdout.decode().splitlines()
        snapshots = {}
        for name in paths:
            if not re.fullmatch(r"snapshots/[A-Za-z0-9_-]+\.gz", name):
                raise ValueError(f"非法快照路径：{name}")
            snapshots[name] = read_blob(root, base, name)
        (root / "dist").mkdir(exist_ok=True)
        (root / "dist/stats.json").write_bytes(stats)
        for name, data in snapshots.items():
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
    marker.write_text(json.dumps({"base": base}), encoding="utf-8")
    return base


@contextmanager
def isolated_tree(root: Path, base: str | None):
    with tempfile.TemporaryDirectory(prefix="adkit-publish-") as temp:
        path = Path(temp) / "tree"
        if base is None:
            tree = git(root, "mktree", data=b"").stdout.decode().strip()
            base = git(root, *IDENTITY, "commit-tree", tree, "-m", "initialize dist").stdout.decode().strip()
        git(root, "worktree", "add", "--detach", str(path), base)
        try:
            yield path
        finally:
            git(root, "worktree", "remove", "--force", str(path))


def write_file(root: Path, name: str, data: bytes):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def push_tree(root: Path, worktree: Path, base: str | None, message: str) -> str:
    git(worktree, "add", "--all")
    if git(worktree, "diff", "--cached", "--quiet", check=False).returncode:
        git(worktree, *IDENTITY, "commit", "-m", message)
    commit = git(worktree, "rev-parse", "HEAD").stdout.decode().strip()
    # Exact expected SHA also protects against external writers or manual resets.
    git(root, "push", f"--force-with-lease={DIST_REF}:{base or ''}", "origin", f"{commit}:{DIST_REF}")
    return commit


def publish(root: Path) -> str:
    marker = state_path(root)
    if not marker.exists():
        raise ValueError("发布前必须先 restore，再运行构建")
    base = json.loads(marker.read_text(encoding="utf-8"))["base"]
    payload = {
        "adkit-adonly.conf": (root / "dist/adkit-adonly.conf").read_bytes(),
        "stats.json": (root / "dist/stats.json").read_bytes(),
    }
    checked_stats(payload["stats.json"])
    for name, pending in CHANNEL_FILES:
        payload[f"latest/{name}"] = (root / "dist/latest" / name).read_bytes()
        payload[pending] = (root / "dist/stable" / name).read_bytes()
        if base is None:
            old_stable = None
        elif name == "adkit.conf":
            # The existing full configuration must never be advanced by migration.
            old_stable = read_blob(root, base, f"stable/{name}")
        else:
            old_stable = read_optional_blob(root, base, f"stable/{name}")
        payload[f"stable/{name}"] = old_stable if old_stable is not None else payload[pending]
    for path in sorted((root / "snapshots").glob("*.gz")):
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.gz", path.name):
            raise ValueError(f"非法快照路径：{path.name}")
        payload[f"snapshots/{path.name}"] = path.read_bytes()
    if not all(payload.values()):
        raise ValueError("构建产物为空，停止发布")
    with isolated_tree(root, base) as tree:
        # Rebuild the index from explicit artifacts, removing any legacy files.
        git(tree, "rm", "-r", "--ignore-unmatch", ".")
        for name, data in payload.items():
            write_file(tree, name, data)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        commit = push_tree(root, tree, base, f"build {now}")
    marker.unlink(missing_ok=True)
    return commit


def promote(root: Path, output: Path) -> str:
    base = fetch_dist(root)
    if base is None:
        raise ValueError("dist 分支不存在，请先完成一次构建")
    checked_stats(read_blob(root, base, "stats.json"))
    # Read every format first: a missing pending artifact must not partially promote.
    pending = {name: read_blob(root, base, path) for name, path in CHANNEL_FILES}
    with isolated_tree(root, base) as tree:
        for name, data in pending.items():
            write_file(tree, f"stable/{name}", data)
        commit = push_tree(root, tree, base, "promote stable")
        assets = tuple(f"stable/{name}" for name, _ in CHANNEL_FILES) + ("adkit-adonly.conf", "stats.json")
        for name in assets:
            write_file(output, name, read_blob(root, commit, name))
    return commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("restore", "publish", "promote"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/release")
    args = parser.parse_args()
    try:
        if args.command == "restore":
            commit = restore(args.root)
        elif args.command == "publish":
            commit = publish(args.root)
        else:
            commit = promote(args.root, args.output)
        print(commit or "bootstrap")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write(f"sha={commit or ''}\n")
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr.decode(errors="replace"))
        else:
            print(error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
