#!/usr/bin/env python3
"""
cross_reference_malicious.py
============================

Cross-reference the LinkedIn extension-probe list (`probed-extension-ids.txt`)
against the community-maintained malicious-extension database at
https://github.com/toborrm9/malicious_extension_sentry .

Outputs:
- data/malicious-db-snapshot.csv   raw snapshot of toborrm9's CSV at run time
- data/malicious-overlap.csv       just the overlapping rows (sortable / Excelable)
- reports/MALICIOUS_OVERLAP.md     human-readable findings, ready to commit

Usage:
    python3 scripts/cross_reference_malicious.py
    python3 scripts/cross_reference_malicious.py --offline data/malicious-db-snapshot.csv

The script works fully offline once the snapshot has been downloaded.
No third-party dependencies. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LINKEDIN_LIST = REPO_ROOT / "probed-extension-ids.txt"
DATA_DIR = REPO_ROOT / "data"
REPORTS_DIR = REPO_ROOT / "reports"
SNAPSHOT_PATH = DATA_DIR / "malicious-db-snapshot.csv"
OVERLAP_CSV = DATA_DIR / "malicious-overlap.csv"
REPORT_MD = REPORTS_DIR / "MALICIOUS_OVERLAP.md"

MALICIOUS_DB_URL = (
    "https://raw.githubusercontent.com/toborrm9/"
    "malicious_extension_sentry/main/malicious_extensions_detailed.csv"
)


def fetch_malicious_db(dest: Path) -> None:
    """Download the toborrm9 malicious-extension CSV to `dest`."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] fetching {MALICIOUS_DB_URL}", file=sys.stderr)
    req = urllib.request.Request(
        MALICIOUS_DB_URL,
        headers={"User-Agent": "linkedin-spyware-analysis/1.0 (+research)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as out:
        out.write(resp.read())
    print(f"[+] wrote {dest} ({dest.stat().st_size} bytes)", file=sys.stderr)


def load_linkedin_ids(path: Path) -> set[str]:
    with open(path) as f:
        return {line.strip() for line in f if line.strip()}


def load_malicious_db(path: Path) -> list[dict]:
    """Returns a list of dicts with at least: extension_id, name, reason, source, insert_date_fmt."""
    rows: list[dict] = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ext_id = (row.get("extension_id") or "").strip().lower()
            if len(ext_id) != 32 or any(c not in "abcdefghijklmnop" for c in ext_id):
                continue
            row["extension_id"] = ext_id
            rows.append(row)
    return rows


def write_overlap_csv(overlap_rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["extension_id", "name", "reason", "source", "insert_date_fmt"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in overlap_rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})


def write_markdown_report(
    overlap_rows: list[dict],
    linkedin_count: int,
    malicious_count: int,
    snapshot_path: Path,
    out_path: Path,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    overlap_count = len(overlap_rows)
    pct_of_linkedin = 100 * overlap_count / linkedin_count if linkedin_count else 0.0
    pct_of_db = 100 * overlap_count / malicious_count if malicious_count else 0.0
    not_in_db_share = 100 * (linkedin_count - overlap_count) / linkedin_count if linkedin_count else 0.0
    reason_counts = Counter((r.get("reason") or "").strip() for r in overlap_rows)
    snapshot_mtime = datetime.fromtimestamp(
        snapshot_path.stat().st_mtime, tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# Cross-reference: LinkedIn probes ∩ malicious-extension database")
    lines.append("")
    lines.append(
        "How much of LinkedIn's 6,222-entry extension probe list overlaps "
        "with extensions that have been independently classified as "
        "malicious, suspicious, or policy-violating?"
    )
    lines.append("")
    lines.append("## Sources")
    lines.append("")
    lines.append(
        f"- **LinkedIn probe list:** [`probed-extension-ids.txt`](../probed-extension-ids.txt) "
        f"({linkedin_count:,} unique IDs) — extracted from the LinkedIn web client bundle. "
        f"See [`README.md`](../README.md) for capture details."
    )
    lines.append(
        f"- **Malicious DB:** [`toborrm9/malicious_extension_sentry`](https://github.com/toborrm9/malicious_extension_sentry) "
        f"({malicious_count:,} unique IDs in `malicious_extensions_detailed.csv` at snapshot time). "
        f"Categories: Malware, Policy Violation, Bundling Unwanted Software, "
        f"In store but Suspicious, In store but not whitelisted, Removal reason Unknown, etc."
    )
    lines.append(
        f"- **Snapshot taken:** {snapshot_mtime} "
        f"(local copy at [`data/malicious-db-snapshot.csv`](../data/malicious-db-snapshot.csv))."
    )
    lines.append("")
    lines.append("## Headline numbers")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append(f"| LinkedIn probe list (unique IDs) | **{linkedin_count:,}** |")
    lines.append(f"| Malicious DB (unique IDs) | **{malicious_count:,}** |")
    lines.append(f"| **Overlap** (in BOTH lists) | **{overlap_count}** |")
    lines.append(f"| Overlap as % of LinkedIn probe list | **{pct_of_linkedin:.2f}%** |")
    lines.append(f"| Overlap as % of malicious DB | **{pct_of_db:.2f}%** |")
    lines.append(
        f"| Probes targeting extensions with **no** known-malicious classification | "
        f"**{linkedin_count - overlap_count:,}** ({not_in_db_share:.2f}%) |"
    )
    lines.append("")
    lines.append("## Two readings of the same numbers")
    lines.append("")
    lines.append(
        "**Reading A — narrowly defensible.** When LinkedIn's probe list does "
        "intersect the malicious DB, the matched extensions are overwhelmingly "
        "tools whose stated purpose is to scrape, automate, or otherwise abuse "
        "LinkedIn itself (cookie importers, prospecting / lead-gen extensions, "
        "Sales Navigator scrapers, fake-engagement tools). For that narrow "
        "slice, \"anti-abuse telemetry\" is a defensible framing."
    )
    lines.append("")
    not_in_db = linkedin_count - overlap_count
    lines.append(
        f"**Reading B — what the bulk of the list is doing.** That defensible "
        f"slice is **{pct_of_linkedin:.2f}% of the probe list**. The other "
        f"**{not_in_db_share:.2f}%** of the extensions LinkedIn fingerprints "
        f"on every Chromium pageview have **no** classification in a curated "
        f"malicious-extension database. Whatever LinkedIn is doing with those "
        f"{not_in_db:,} probes, \"checking for known-malicious extensions\" "
        f"is not a complete explanation."
    )
    lines.append("")
    lines.append(
        "Both readings are simultaneously true, and that is the most "
        "interesting thing about the dataset."
    )
    lines.append("")

    if reason_counts:
        lines.append("## Overlap breakdown by malicious-DB reason")
        lines.append("")
        lines.append("| reason | count |")
        lines.append("|---|---|")
        for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1]):
            r = reason or "(blank)"
            lines.append(f"| {r} | {count} |")
        lines.append("")

    lines.append("## Full overlap")
    lines.append("")
    lines.append(
        "Each row is an extension that appears on **both** LinkedIn's hardcoded "
        "probe list and the toborrm9 malicious-extension database at snapshot time. "
        "Look any ID up at "
        "`https://chromewebstore.google.com/detail/<id>` (returns 404 if delisted)."
    )
    lines.append("")
    lines.append("| ID | Name | Reason | DB source | Added |")
    lines.append("|---|---|---|---|---|")
    for r in sorted(overlap_rows, key=lambda x: (x.get("reason") or "", (x.get("name") or "").lower())):
        ext_id = r["extension_id"]
        name = (r.get("name") or "").replace("|", "\\|").strip()
        reason = (r.get("reason") or "").replace("|", "\\|").strip()
        source = (r.get("source") or "").replace("|", "\\|").strip()
        added = (r.get("insert_date_fmt") or "").strip()
        lines.append(f"| `{ext_id}` | {name} | {reason} | {source} | {added} |")
    lines.append("")

    lines.append("## Reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 scripts/cross_reference_malicious.py")
    lines.append("```")
    lines.append("")
    lines.append(
        "The script downloads the latest malicious-DB CSV at run time and "
        "regenerates this report. Snapshots are saved to `data/` so the "
        "comparison is reproducible even if upstream changes."
    )
    lines.append("")

    out_path.write_text("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument(
        "--offline",
        type=Path,
        help="Path to a previously-downloaded malicious-DB CSV. "
        "Skips the network fetch.",
    )
    ap.add_argument(
        "--linkedin-list",
        type=Path,
        default=LINKEDIN_LIST,
        help=f"Path to LinkedIn probe list (default: {LINKEDIN_LIST.relative_to(REPO_ROOT)}).",
    )
    args = ap.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.offline:
        snapshot = args.offline
    else:
        fetch_malicious_db(SNAPSHOT_PATH)
        snapshot = SNAPSHOT_PATH

    linkedin_ids = load_linkedin_ids(args.linkedin_list)
    malicious_rows = load_malicious_db(snapshot)
    malicious_ids = {r["extension_id"] for r in malicious_rows}

    overlap_ids = linkedin_ids & malicious_ids
    overlap_rows = [r for r in malicious_rows if r["extension_id"] in overlap_ids]

    write_overlap_csv(overlap_rows, OVERLAP_CSV)
    write_markdown_report(
        overlap_rows,
        linkedin_count=len(linkedin_ids),
        malicious_count=len(malicious_ids),
        snapshot_path=snapshot,
        out_path=REPORT_MD,
    )

    print(f"[+] LinkedIn unique IDs:   {len(linkedin_ids):,}", file=sys.stderr)
    print(f"[+] Malicious-DB IDs:      {len(malicious_ids):,}", file=sys.stderr)
    print(f"[+] Overlap:               {len(overlap_ids)}", file=sys.stderr)
    print(f"[+] Wrote {OVERLAP_CSV.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"[+] Wrote {REPORT_MD.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
