#!/usr/bin/env python3
"""
chrome_stats_client.py
======================

Thin, dependency-free client for the Chrome-Stats API
(https://chrome-stats.com/). Used as the primary data source for the
CRXray analysis layer (see docs/CRXRAY_PROPOSAL.md).

Auth:
    Header `x-api-key: <YOUR_KEY>`. Read from the `CHROME_STATS_API_KEY`
    env var, which loaders below pull out of `.env` if present.

Quotas (per Chrome-Stats):
    - Free:    100 requests / month
    - Pro:     1,000 requests / day
    - Premium: 10,000 requests / day
    - Enterprise: unlimited (be courteous)

This client:
    - Loads the key from .env (no python-dotenv dependency).
    - Retries with backoff on 429 / 5xx / network errors.
    - Caches per-extension responses to a JSON-Lines file so reruns
      don't burn quota; resumable.
    - Never echoes the API key to stdout/stderr.

Endpoints implemented:
    detail(ext_id)              -> /api/detail
    list_versions(ext_id)       -> /api/list-versions
    download(ext_id, ...)       -> /api/download                (returns bytes; binary)
    trends(ext_id, num_days)    -> /api/trends
    reviews(ext_id, ...)        -> /api/reviews
    advanced_search(...)        -> /api/{platform}/advanced-search
    search_source(q, ...)       -> /api/{platform}/search-source

CLI:
    python3 scripts/chrome_stats_client.py <id>
    python3 scripts/chrome_stats_client.py --bulk <id-file> --out <jsonl-file>
    python3 scripts/chrome_stats_client.py --show-env       # redacted env summary
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / ".env"

BASE_URL = "https://chrome-stats.com"
AUTH_HEADER = "x-api-key"
USER_AGENT = "crxray/0.1 (+https://github.com/jaylane/linkedin-spyware-analysis)"

DEFAULT_TIMEOUT_S = 30
DEFAULT_RETRIES = 4
DEFAULT_BACKOFF_S = 2.0


# ----------------------------------------------------------------------------
# .env loader (stdlib only)
# ----------------------------------------------------------------------------

def load_env(path: Path = ENV_PATH) -> dict[str, str]:
    """Minimal .env loader. Doesn't expand variables, handles simple quoting."""
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def populate_env_from_dotenv() -> None:
    for k, v in load_env().items():
        os.environ.setdefault(k, v)


# ----------------------------------------------------------------------------
# Client
# ----------------------------------------------------------------------------

class ChromeStatsError(Exception):
    pass


class ChromeStatsRateLimited(ChromeStatsError):
    pass


class ChromeStatsClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = BASE_URL,
        timeout: int = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_RETRIES,
        backoff_s: float = DEFAULT_BACKOFF_S,
    ) -> None:
        if api_key is None:
            populate_env_from_dotenv()
            api_key = os.environ.get("CHROME_STATS_API_KEY", "")
        if not api_key:
            raise ChromeStatsError(
                "no API key found — set CHROME_STATS_API_KEY in .env "
                "(see .env.example)"
            )
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_s = backoff_s

    # ---- low-level ----

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        return_bytes: bool = False,
    ) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"

        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, method=method)
            req.add_header(AUTH_HEADER, self._api_key)
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", USER_AGENT)
            if json_body is not None:
                req.data = json.dumps(json_body).encode()
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read()
                    if return_bytes:
                        return raw
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as e:
                # Don't put the API key into any error message we raise.
                detail = ""
                try:
                    detail = e.read().decode("utf-8", errors="replace")[:300]
                except Exception:
                    pass
                if e.code == 429:
                    if attempt < self.max_retries:
                        sleep = self.backoff_s * (2 ** attempt) + random.random()
                        time.sleep(sleep)
                        continue
                    raise ChromeStatsRateLimited(
                        f"HTTP 429 on {method} {path} after {attempt+1} tries: {detail}"
                    ) from e
                if 500 <= e.code < 600 and attempt < self.max_retries:
                    time.sleep(self.backoff_s * (2 ** attempt) + random.random())
                    continue
                raise ChromeStatsError(
                    f"HTTP {e.code} on {method} {path}: {detail}"
                ) from e
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt < self.max_retries:
                    time.sleep(self.backoff_s * (2 ** attempt) + random.random())
                    continue
                raise ChromeStatsError(f"network error on {method} {path}: {e}") from e

    # ---- public methods (matching the OpenAPI spec) ----

    def detail(self, extension_id: str) -> dict:
        """GET /api/detail — full extension metadata (57 fields incl. risk)."""
        return self._request("GET", "/api/detail", params={"id": extension_id})

    def list_versions(self, extension_id: str) -> dict:
        """GET /api/list-versions — list of downloadable versions."""
        return self._request("GET", "/api/list-versions", params={"id": extension_id})

    def trends(self, extension_id: str, num_days: int = 30) -> dict:
        """GET /api/trends — historical user-count / rating trends."""
        return self._request(
            "GET", "/api/trends",
            params={"id": extension_id, "numDays": num_days},
        )

    def reviews(self, extension_id: str, **params: Any) -> dict:
        """GET /api/reviews — user reviews."""
        return self._request(
            "GET", "/api/reviews",
            params={"id": extension_id, **params},
        )

    def download(
        self, extension_id: str,
        version: str = "latest",
        type_: str = "crx",
        version_code: str | None = None,
    ) -> bytes:
        """GET /api/download — returns the raw CRX/ZIP bytes."""
        params: dict[str, Any] = {"id": extension_id, "type": type_, "version": version}
        if version_code is not None:
            params["versionCode"] = version_code
        return self._request("GET", "/api/download", params=params, return_bytes=True)

    def advanced_search(
        self, body: dict, platform: str = "chrome",
    ) -> dict:
        """POST /api/{platform}/advanced-search — Premium only."""
        return self._request(
            "POST", f"/api/{platform}/advanced-search", json_body=body,
        )

    def search_source(
        self, query: str,
        platform: str = "chrome",
        extension_id: str | None = None,
        page: int = 1,
    ) -> list[dict]:
        """GET /api/{platform}/search-source — Premium only.

        Search across the source code of every indexed extension's latest version.
        Indexes only *.js and *.json files.
        """
        params: dict[str, Any] = {"q": query, "page": page}
        if extension_id:
            params["id"] = extension_id
        return self._request(
            "GET", f"/api/{platform}/search-source", params=params,
        )


# ----------------------------------------------------------------------------
# Bulk fetcher with on-disk JSON-Lines cache (resumable, never re-fetches)
# ----------------------------------------------------------------------------

def fetch_details_bulk(
    ids: Iterable[str],
    out_path: Path,
    client: ChromeStatsClient | None = None,
    delay_s: float = 0.10,
    progress_every: int = 25,
) -> dict[str, int]:
    """Fetch /api/detail for each ID, append to JSONL. Resumable.

    Returns counts: {"new": N, "skipped": N, "errors": N}.
    """
    client = client or ChromeStatsClient()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    if out_path.exists():
        with out_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if isinstance(rec, dict) and rec.get("id"):
                        seen.add(rec["id"])
                except Exception:
                    pass

    new = 0
    errors = 0
    skipped = 0
    todo = [i for i in ids if i not in seen]
    if not todo:
        return {"new": 0, "skipped": len(seen), "errors": 0}

    with out_path.open("a", encoding="utf-8") as out_f:
        for i, ext_id in enumerate(todo, 1):
            try:
                rec = client.detail(ext_id)
                if not isinstance(rec, dict):
                    rec = {"id": ext_id, "_error": "non-dict response"}
                    errors += 1
                else:
                    new += 1
                rec.setdefault("id", ext_id)
                out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                out_f.flush()
            except ChromeStatsRateLimited as e:
                # Hard stop on persistent rate-limit; safe to resume later.
                print(f"[!] rate-limited; stopping. {e}", file=sys.stderr)
                break
            except ChromeStatsError as e:
                errors += 1
                err = {"id": ext_id, "_error": str(e)[:300]}
                out_f.write(json.dumps(err) + "\n")
                out_f.flush()
            if i % progress_every == 0:
                total = len(todo)
                print(
                    f"[+] {i}/{total}  (new={new}, errors={errors}, prev_cached={len(seen)})",
                    file=sys.stderr,
                )
            if delay_s > 0:
                time.sleep(delay_s)

    skipped = len(seen)
    return {"new": new, "skipped": skipped, "errors": errors}


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def _print_redacted_env() -> None:
    env = load_env()
    if not env:
        print("[!] no .env file found", file=sys.stderr)
        return
    for k, v in env.items():
        redacted = (v[:4] + "…" + v[-4:]) if v and len(v) > 10 else "(empty)"
        print(f"  {k:<32} {redacted}", file=sys.stderr)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("extension_id", nargs="?",
                   help="Extension ID to look up. Prints raw /api/detail JSON.")
    p.add_argument("--bulk", type=Path,
                   help="Path to a file of extension IDs (one per line).")
    p.add_argument("--out", type=Path,
                   default=REPO_ROOT / "data" / "chrome-stats-detail.jsonl",
                   help="Output JSONL path for --bulk mode.")
    p.add_argument("--delay", type=float, default=0.10,
                   help="Per-request delay in seconds (default 0.10).")
    p.add_argument("--show-env", action="store_true",
                   help="Print which .env keys are loaded (values redacted).")
    args = p.parse_args()

    populate_env_from_dotenv()

    if args.show_env:
        _print_redacted_env()
        return 0

    client = ChromeStatsClient()

    if args.bulk:
        ids = [
            line.strip()
            for line in args.bulk.read_text().splitlines()
            if line.strip() and len(line.strip()) == 32
        ]
        print(f"[+] {len(ids):,} IDs in {args.bulk.name}", file=sys.stderr)
        counts = fetch_details_bulk(
            ids, out_path=args.out, client=client, delay_s=args.delay,
        )
        print(f"[+] done. new={counts['new']:,} "
              f"skipped={counts['skipped']:,} errors={counts['errors']:,}",
              file=sys.stderr)
        try:
            shown = args.out.resolve().relative_to(REPO_ROOT)
        except ValueError:
            shown = args.out
        print(f"[+] wrote {shown}", file=sys.stderr)
        return 0

    if not args.extension_id:
        p.print_help()
        return 1

    rec = client.detail(args.extension_id)
    print(json.dumps(rec, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
