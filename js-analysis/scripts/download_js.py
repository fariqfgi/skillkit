#!/usr/bin/env python3 -I
"""
Download JS files from a list of URLs. Skips files over size limit.

Usage:
    python3 download_js.py urls.txt output_dir/ [--max-files 200] [--max-size-kb 2048]
"""
import argparse
import hashlib
import sys
import urllib.request
import urllib.error
from pathlib import Path


def safe_filename(url: str, idx: int) -> str:
    h = hashlib.md5(url.encode()).hexdigest()[:8]
    name = url.split("?")[0].rstrip("/").split("/")[-1]
    name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
    if not name.endswith(".js"):
        name += ".js"
    return f"{idx:04d}_{h}_{name}"[:120]


def download(url: str, dest: Path, max_size: int, timeout: int = 15) -> bool:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; security-researcher-bot/1.0)",
                "Accept-Encoding": "gzip, deflate",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Check content-length header first
            cl = resp.headers.get("Content-Length")
            if cl and int(cl) > max_size:
                return False
            data = resp.read(max_size + 1)
            if len(data) > max_size:
                return False
            dest.write_bytes(data)
            return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("urls_file")
    parser.add_argument("output_dir")
    parser.add_argument("--max-files", type=int, default=200)
    parser.add_argument("--max-size-kb", type=int, default=2048)
    args = parser.parse_args()

    urls_path = Path(args.urls_file)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not urls_path.exists():
        print(f"[!] URL file not found: {urls_path}", file=sys.stderr)
        sys.exit(1)

    urls = [u.strip() for u in urls_path.read_text().splitlines() if u.strip()]
    max_size = args.max_size_kb * 1024
    downloaded = 0
    skipped = 0

    for idx, url in enumerate(urls):
        if downloaded >= args.max_files:
            print(f"[!] Reached max-files limit ({args.max_files}), stopping.")
            break
        fname = safe_filename(url, idx)
        dest = out_dir / fname
        if dest.exists():
            downloaded += 1
            continue
        ok = download(url, dest, max_size)
        if ok:
            downloaded += 1
        else:
            skipped += 1

    print(f"[+] Downloaded: {downloaded}, Skipped/failed: {skipped}")


if __name__ == "__main__":
    main()
