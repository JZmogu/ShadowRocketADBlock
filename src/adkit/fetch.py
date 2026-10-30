"""下载候选规则并验证；只有完整构建成功后才保存有效快照。"""
from __future__ import annotations

import gzip
import http.client
import os
import pathlib
import re
import tempfile
import time
import urllib.request
import zlib

from .parsers import PARSERS


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
_CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+)")


def _validator(headers):
    etag = headers.get("ETag")
    if etag and not etag.startswith("W/"):
        return "ETag", etag
    modified = headers.get("Last-Modified")
    return ("Last-Modified", modified) if modified else None


def http_get(url: str, tries: int = 14, timeout: int = 120, chunk: int = 1 << 16) -> bytes:
    """续传只拼接同版本、连续且完整的 206 响应；200 始终替换旧缓冲区。"""
    if tries < 1 or chunk < 1:
        raise ValueError("tries 和 chunk 必须为正数")
    buf = bytearray()
    total = None
    validator = None
    full_request = False
    failures = 0
    chunk0 = chunk
    last = None
    while failures < tries:
        start = len(buf)
        end = start + chunk - 1 if total is None else min(total - 1, start + chunk - 1)
        headers = {"User-Agent": UA, "Accept-Encoding": "identity"}
        if not full_request:
            headers["Range"] = f"bytes={start}-{end}"
            if start and validator:
                headers["If-Range"] = validator[1]
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    # Range 被忽略，或者 If-Range 指向的版本已更新：整个响应是新文件。
                    buf.clear()
                    total = None
                    validator = None
                    full_request = True
                    data = response.read()
                    length = response.headers.get("Content-Length")
                    if length is not None and len(data) != int(length):
                        raise ValueError("200 响应长度与 Content-Length 不一致")
                    return data
                if response.status != 206:
                    raise ValueError(f"不支持的 HTTP 状态 {response.status}")
                match = _CONTENT_RANGE.fullmatch(response.headers.get("Content-Range", ""))
                if not match:
                    raise ValueError("206 响应缺少有效 Content-Range")
                first, final, size = map(int, match.groups())
                if first != start or final < first or final >= size:
                    raise ValueError("Content-Range 起点或长度不一致")
                if total is not None and size != total:
                    raise ValueError("续传期间文件长度发生变化")
                if not full_request and final > end:
                    raise ValueError("206 响应超出请求范围")
                current_validator = _validator(response.headers)
                if start and (validator is None or current_validator != validator):
                    raise ValueError("续传期间文件版本发生变化或无法验证")
                if full_request and final + 1 != size:
                    raise ValueError("完整下载请求仍收到不完整的 206 响应")
                if final + 1 < size and current_validator is None:
                    # 没有版本标识，宁可重新下载整个文件，也不拼接不同版本。
                    buf.clear()
                    total = None
                    full_request = True
                    continue
                data = response.read()
                length = response.headers.get("Content-Length")
                if len(data) != final - first + 1 or (length is not None and len(data) != int(length)):
                    raise ValueError("206 响应体长度与声明范围不一致")
            buf.extend(data)
            total = size
            validator = current_validator
            if len(buf) == total:
                return bytes(buf)
            failures = 0
            chunk = chunk0
        except ValueError as exc:
            # 元数据不一致时，已经下载的前缀也不能继续使用。
            buf.clear()
            total = None
            validator = None
            full_request = True
            failures += 1
            last = exc
        except (OSError, http.client.HTTPException) as exc:
            # 不采用不完整的响应体，下轮重新请求该范围。
            failures += 1
            last = exc
            chunk = max(1, chunk // 2)
        if failures:
            print(f"    下载重试: {url}: {last}", flush=True)
            if failures < tries:
                time.sleep(min(2 * failures, 10))
    raise RuntimeError(f"{url}（已收 {len(buf)}B/{total}B）: {last}")


def _checked(source, data, validate):
    text = data.decode("utf-8-sig")
    rules, _ = PARSERS[source["parser"]](text, source["id"])
    minimum = max(1, source.get("min_rules", 1))
    if len(rules) < minimum:
        raise ValueError(f"有效规则仅 {len(rules)} 条，低于单源下限 {minimum}")
    if validate:
        validate(source, text)
    return text, len(rules)


def load_sources(cfg, cache_dir: pathlib.Path, snap_dir: pathlib.Path, live: bool = True,
                 only_ids=None, pending=None, validate=None):
    """返回 [(id, text|None, warning|None)]，不修改磁盘。

    有效候选暂存到 pending；调用方通过全部质量检查后调用 commit_sources。
    validate(source, text) 可抛出 ValueError 拒绝候选和本地回退内容。
    """
    out = []
    for source in cfg["sources"]:
        if not source.get("enabled", True):
            continue
        sid = source["id"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", sid):
            raise ValueError(f"无效来源 id: {sid!r}")
        errors = []
        local = None
        # snapshots 只在完整构建成功后提交，优先于可能来自旧版本的 cache。
        for label, path in (("snapshot", snap_dir / f"{sid}.gz"), ("cache", cache_dir / f"{sid}.txt")):
            if not path.exists():
                continue
            try:
                data = path.read_bytes()
                if label == "snapshot":
                    data = gzip.decompress(data)
                text, count = _checked(source, data, validate)
                local = (label, data, text, count)
                break
            except (OSError, EOFError, ValueError, zlib.error) as exc:
                errors.append(f"{label} 无效: {exc}")
        use_live = live and (only_ids is None or sid in only_ids)
        if use_live:
            accepted = False
            for url in [source["url"]] + list(source.get("fallback_urls", [])):
                try:
                    data = http_get(url)
                    text, count = _checked(source, data, validate)
                    threshold = source.get("max_deviation", 0.4)
                    if local and abs(count - local[3]) / local[3] > threshold:
                        raise ValueError(f"规则数 {local[3]} -> {count}，偏移超过 {threshold:.0%}")
                except (OSError, EOFError, ValueError, RuntimeError) as exc:
                    errors.append(f"{url}: {exc}")
                    continue
                if pending is not None:
                    pending[sid] = data
                out.append((sid, text, "; ".join(errors) or None))
                accepted = True
                break
            if accepted:
                continue
        if local:
            label, data, text, _ = local
            if pending is not None:
                pending[sid] = data
            prefix = f"抓取或校验失败，已回退 {label}" if use_live else f"offline({label})"
            out.append((sid, text, "; ".join([prefix] + errors)))
        else:
            out.append((sid, None, "; ".join(errors) or "本地无有效副本"))
    return out


def _atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
            temporary = pathlib.Path(output.name)
            output.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def commit_sources(pending, cache_dir: pathlib.Path, snap_dir: pathlib.Path):
    """完整构建通过后，原子替换每个来源的 cache 和有效快照。"""
    for sid, data in pending.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]+", sid):
            raise ValueError(f"无效来源 id: {sid!r}")
        _atomic_write(snap_dir / f"{sid}.gz", gzip.compress(data, mtime=0))
        _atomic_write(cache_dir / f"{sid}.txt", data)
