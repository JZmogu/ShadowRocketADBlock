"""源文件抓取：urllib（自动走系统代理）、重试、cache/ 与 snapshots/ 双份落盘。

snapshots/ 是上一份成功快照：任何源 404/改版/被墙，构建自动回退到快照，永不因上游抖动开天窗。
snapshots/ 纳入 git（小文件 gzip），GitHub Actions 里天然兜底。
"""
from __future__ import annotations

import gzip
import pathlib
import time
import urllib.request


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def http_get(url: str, tries: int = 14, timeout: int = 120, chunk: int = 1 << 16) -> bytes:
    """断点续传式分段下载 + 自适应段长：同一位置反复失败就把段长减半（专治
    anti-ad.net 掐连接、GitHub raw 中途 429/断流）；服务器不支持 Range 时一次读完。"""
    import http.client

    buf = bytearray()
    total = None
    stalls = 0
    last = None
    chunk0 = chunk
    for _ in range(tries * 4):
        if total is not None and len(buf) >= total:
            break
        start = len(buf)
        end = (start + chunk - 1) if total is None else min(total - 1, start + chunk - 1)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Range": f"bytes={start}-{end}"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                cr = r.headers.get("Content-Range")
                full = not (r.status == 206 and cr)
                if not full:
                    total = int(cr.rsplit("/", 1)[-1])
                data = r.read()
            buf += data
            if full:
                print(f"    ↓ {url.split('/')[-1]}: {len(buf) / 1024:.0f} KB (200 全量)", flush=True)
                return bytes(buf)
            print(f"    ↓ {url.split('/')[-1]}: {len(buf) / 1024:.0f}/{total / 1024:.0f} KB", flush=True)
            if stalls:
                stalls = 0
                chunk = chunk0  # 恢复段长
        except http.client.IncompleteRead as e:
            buf += e.partial  # 半段数据收下，下轮从这里续传
            stalls += 1
            last = e
            chunk = max(1 << 12, chunk // 2)  # 自适应缩小段长
            print(f"    续传（半段）: {url.split('/')[-1]} 已收 {len(buf) / 1024:.0f} KB，段长→{chunk // 1024}KB: {e}", flush=True)
        except Exception as e:  # noqa: BLE001
            stalls += 1
            last = e
            chunk = max(1 << 12, chunk // 2)
            print(f"    重试: {url}: {e}，段长→{chunk // 1024}KB", flush=True)
        if stalls >= tries:
            raise RuntimeError(f"{url}（已收 {len(buf)}B/{total}B）: {last}")
        if stalls:
            time.sleep(min(2 * stalls, 10))
    if total is not None and len(buf) != total:
        raise RuntimeError(f"{url}: 拼接不完整 {len(buf)} != {total}")
    return bytes(buf)


def load_sources(cfg, cache_dir: pathlib.Path, snap_dir: pathlib.Path, live: bool = True, only_ids=None):
    """返回 [(source_id, text|None, warn|None)]。only_ids 指定时其余源直接用本地 cache。"""
    out = []
    cache_dir.mkdir(exist_ok=True)
    snap_dir.mkdir(exist_ok=True)
    for s in cfg["sources"]:
        if not s.get("enabled", True):
            continue
        sid = s["id"]
        snap = snap_dir / f"{sid}.gz"
        use_live = live and (only_ids is None or sid in only_ids)
        if use_live:
            data = None
            errs = []
            for u in [s["url"]] + list(s.get("fallback_urls", [])):
                try:
                    data = http_get(u)
                    break
                except Exception as e:  # noqa: BLE001
                    errs.append(str(e))
            if data is not None:
                (cache_dir / f"{sid}.txt").write_bytes(data)
                snap.write_bytes(gzip.compress(data))
                out.append((sid, data.decode("utf-8", "replace"), None))
                continue
            if snap.exists():
                text = gzip.decompress(snap.read_bytes()).decode("utf-8", "replace")
                out.append((sid, text, f"抓取失败已回退快照: {errs[-1]}"))
                continue
            out.append((sid, None, f"抓取失败且无快照: {errs[-1] if errs else '?'}"))
            continue
        c = cache_dir / f"{sid}.txt"
        if c.exists():
            out.append((sid, c.read_text("utf-8", "replace"), "cache" if live else "offline(cache)"))
        elif snap.exists():
            out.append((sid, gzip.decompress(snap.read_bytes()).decode("utf-8", "replace"), "snapshot"))
        else:
            out.append((sid, None, "本地无副本"))
    return out
