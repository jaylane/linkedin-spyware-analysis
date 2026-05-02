#!/usr/bin/env python3
"""
fetch_extension_metadata.py
===========================

For each extension ID in `probed-extension-ids.txt`, fetch the Chrome Web Store
listing page and extract metadata (name, description, status). Output is written
incrementally to `data/extension-metadata.csv`, so the script is resumable —
re-running picks up where it left off.

This is the slow companion to `cross_reference_malicious.py`. Where the
cross-reference is instant (just an in-memory set intersection), this script
makes thousands of HTTP requests to chromewebstore.google.com. Expect:

    - 6,222 IDs × ~250 ms/req ÷ 8 workers ≈ 3-5 minutes optimistic
    - With Google rate-limiting, retries, and 404s          ≈ 15-45 minutes
    - Worst-case (rate-limit storm)                         ≈ 1-2 hours

Output schema (data/extension-metadata.csv):
    extension_id, name, short_description, status, fetched_at, http_status

Where status ∈ {"published", "removed", "error"}.

Standard library only — no `requests`, no `bs4`. Easy to audit.

Usage:
    python3 scripts/fetch_extension_metadata.py
    python3 scripts/fetch_extension_metadata.py --limit 50              # test run
    python3 scripts/fetch_extension_metadata.py --workers 4 --delay 0.5
    python3 scripts/fetch_extension_metadata.py --resume                # default
    python3 scripts/fetch_extension_metadata.py --no-resume             # restart
"""

from __future__ import annotations

import argparse
import csv
import html
import os
import random
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LINKEDIN_LIST = REPO_ROOT / "probed-extension-ids.txt"
DATA_DIR = REPO_ROOT / "data"
OUT_PATH = DATA_DIR / "extension-metadata.csv"

CWS_URL = "https://chromewebstore.google.com/detail/{id}"

# Realistic User-Agent. We're not pretending to be a unique person — this is a
# common UA that minimises the chance of getting flagged as automation while
# also not being deceptive (the script identifies itself in the README).
DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/147.0.0.0 Safari/537.36"
)

# Chrome Web Store inserts og:* meta tags near the top of the response.
# These regexes are intentionally lenient — order/quoting varies.
RE_OG_TITLE = re.compile(
    r'<meta[^>]+property="og:title"[^>]+content="([^"]*)"', re.I
)
RE_OG_DESC = re.compile(
    r'<meta[^>]+property="og:description"[^>]+content="([^"]*)"', re.I
)
RE_META_DESC = re.compile(
    r'<meta[^>]+name="description"[^>]+content="([^"]*)"', re.I
)

CSV_FIELDS = [
    "extension_id",
    "name",
    "short_description",
    "status",
    "fetched_at",
    "http_status",
]


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

def fetch_one(ext_id: str, user_agent: str, timeout: int) -> dict:
    """Fetch one extension page and return a row dict."""
    url = CWS_URL.format(id=ext_id)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = {
        "extension_id": ext_id,
        "name": "",
        "short_description": "",
        "status": "error",
        "fetched_at": fetched_at,
        "http_status": "",
    }
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            row["http_status"] = str(resp.status)
            row["status"] = "published"
            row["name"] = _decode(_first(RE_OG_TITLE, body))
            row["short_description"] = _decode(
                _first(RE_OG_DESC, body) or _first(RE_META_DESC, body)
            )
    except urllib.error.HTTPError as e:
        row["http_status"] = str(e.code)
        if e.code == 404:
            row["status"] = "removed"
        elif e.code == 429:
            row["status"] = "rate_limited"
        else:
            row["status"] = f"http_{e.code}"
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        row["http_status"] = type(e).__name__
        row["status"] = "network_error"
    return row


def _first(regex: re.Pattern, text: str) -> str:
    m = regex.search(text)
    return m.group(1) if m else ""


def _decode(s: str) -> str:
    return html.unescape(s).strip() if s else ""


# ----------------------------------------------------------------------------
# Resume / output
# ----------------------------------------------------------------------------

def already_fetched_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    seen: set[str] = set()
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ext_id = (row.get("extension_id") or "").strip().lower()
            if ext_id:
                seen.add(ext_id)
    return seen


def open_writer(path: Path, append: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append and path.exists() else "w"
    f = open(path, mode, newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
    if mode == "w":
        w.writeheader()
        f.flush()
    return f, w


# ----------------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--linkedin-list", type=Path, default=LINKEDIN_LIST,
                    help=f"Path to LinkedIn probe list (default: {LINKEDIN_LIST.relative_to(REPO_ROOT)}).")
    ap.add_argument("--out", type=Path, default=OUT_PATH,
                    help=f"Output CSV path (default: {OUT_PATH.relative_to(REPO_ROOT)}).")
    ap.add_argument("--workers", type=int, default=8,
                    help="Concurrent fetch workers (default: 8). Be polite. >16 will get rate-limited.")
    ap.add_argument("--delay", type=float, default=0.15,
                    help="Per-worker base delay in seconds between requests (default: 0.15). Jittered.")
    ap.add_argument("--timeout", type=int, default=20,
                    help="Per-request timeout in seconds (default: 20).")
    ap.add_argument("--limit", type=int, default=0,
                    help="Stop after N new fetches (default: 0 = no limit). Useful for smoke-testing.")
    ap.add_argument("--user-agent", default=DEFAULT_UA,
                    help="User-Agent header.")
    ap.add_argument("--no-resume", action="store_true",
                    help="Discard existing CSV and start over. Default is to resume.")
    args = ap.parse_args()

    all_ids = sorted({line.strip() for line in open(args.linkedin_list)
                      if line.strip() and len(line.strip()) == 32})
    print(f"[+] {len(all_ids):,} unique extension IDs in {args.linkedin_list.relative_to(REPO_ROOT)}",
          file=sys.stderr)

    if args.no_resume and args.out.exists():
        args.out.unlink()
    seen = already_fetched_ids(args.out)
    todo = [i for i in all_ids if i not in seen]
    if not todo:
        print(f"[+] {args.out.relative_to(REPO_ROOT)} is already complete "
              f"({len(seen):,}/{len(all_ids):,}). Nothing to do.", file=sys.stderr)
        return 0
    if seen:
        print(f"[+] resuming: {len(seen):,} already fetched, {len(todo):,} remaining",
              file=sys.stderr)
    if args.limit and len(todo) > args.limit:
        todo = todo[: args.limit]
        print(f"[+] --limit {args.limit}: stopping after {len(todo):,} new fetches",
              file=sys.stderr)

    f, writer = open_writer(args.out, append=True)
    write_lock = threading.Lock()
    counts = {"published": 0, "removed": 0, "rate_limited": 0,
              "network_error": 0, "other": 0}

    stop = threading.Event()

    def handle_sigint(signum, frame):
        if not stop.is_set():
            print("\n[!] caught SIGINT — finishing in-flight fetches and exiting cleanly. "
                  "re-run to resume.", file=sys.stderr)
            stop.set()
    signal.signal(signal.SIGINT, handle_sigint)

    def worker(ext_id: str) -> dict:
        if stop.is_set():
            return {}
        if args.delay > 0:
            time.sleep(args.delay + random.random() * args.delay)
        return fetch_one(ext_id, args.user_agent, args.timeout)

    start = time.time()
    completed = 0
    total = len(todo)
    rate_limit_hits = 0
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(worker, eid): eid for eid in todo}
            for fut in as_completed(futures):
                if stop.is_set():
                    break
                row = fut.result()
                if not row:
                    continue
                with write_lock:
                    writer.writerow(row)
                    f.flush()
                completed += 1
                bucket = row["status"] if row["status"] in counts else "other"
                counts[bucket] += 1
                if row["status"] == "rate_limited":
                    rate_limit_hits += 1
                    if rate_limit_hits and rate_limit_hits % 5 == 0:
                        backoff = 5 + random.random() * 10
                        print(f"[!] {rate_limit_hits} rate-limit responses so far; "
                              f"sleeping {backoff:.1f}s to recover",
                              file=sys.stderr)
                        time.sleep(backoff)
                if completed % 50 == 0 or completed == total:
                    elapsed = time.time() - start
                    rate = completed / elapsed if elapsed > 0 else 0
                    eta = (total - completed) / rate if rate > 0 else 0
                    print(f"[+] {completed:,}/{total:,} "
                          f"(pub={counts['published']:,} "
                          f"rem={counts['removed']:,} "
                          f"429={counts['rate_limited']:,} "
                          f"net={counts['network_error']:,}) "
                          f"{rate:.1f}/s  ETA {eta/60:.1f}m",
                          file=sys.stderr)
    finally:
        f.close()

    print(f"\n[+] done. wrote {args.out.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"[+] summary: {counts}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
