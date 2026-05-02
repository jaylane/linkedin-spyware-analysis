#!/usr/bin/env python3
"""
analyze_chrome_stats.py
=======================

Read the JSONL produced by `chrome_stats_client.py --bulk` and emit:

  - data/chrome-stats-summary.csv        flat per-extension summary
  - reports/CHROME_STATS_ANALYSIS.md     human-readable findings

Aggregates currently produced:
  1. Risk-band distribution (riskImpact × riskLikelihood)
  2. LinkedIn-targeting share (extensions requesting linkedin.com access)
  3. CWS removal / blocked / unlisted counts
  4. Update-poisoning candidates       (recent permission additions)
  5. Ownership-transfer candidates     (author email changes)
  6. Category top-N
  7. Top-20 highest-risk extensions
  8. Top-20 most-installed extensions
  9. Cross-reference with toborrm9/malicious_extension_sentry overlap

Usage:
    python3 scripts/analyze_chrome_stats.py
    python3 scripts/analyze_chrome_stats.py --in data/chrome-stats-detail.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IN = REPO_ROOT / "data" / "chrome-stats-detail.jsonl"
SUMMARY_CSV = REPO_ROOT / "data" / "chrome-stats-summary.csv"
REPORT_MD = REPO_ROOT / "reports" / "CHROME_STATS_ANALYSIS.md"
MALICIOUS_SNAPSHOT = REPO_ROOT / "data" / "malicious-db-snapshot.csv"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def load_jsonl(path: Path):
    if not path.exists():
        print(f"[!] no enriched data at {path} — run chrome_stats_client.py --bulk first",
              file=sys.stderr)
        sys.exit(2)
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    out.append(rec)
            except Exception:
                pass
    return out


def load_malicious_db(path: Path) -> dict[str, dict]:
    """Returns map of extension_id -> {name, reason, source, insert_date_fmt}."""
    if not path.exists():
        return {}
    by_id: dict[str, dict] = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            ext_id = (row.get("extension_id") or "").strip().lower()
            if len(ext_id) == 32:
                by_id[ext_id] = row
    return by_id


def has_linkedin_access(rec: dict) -> bool:
    """Does this extension request access to linkedin.com?"""
    risk = rec.get("risk") or {}
    for r in risk.get("riskImpactReasons", []) or []:
        desc = (r.get("description") or "").lower()
        if "linkedin.com" in desc:
            return True
    return False


def linkedin_targeted_domains(rec: dict) -> list[str]:
    """Extract the domain list from access-to-specific-domain reasons."""
    out: list[str] = []
    risk = rec.get("risk") or {}
    for r in risk.get("riskImpactReasons", []) or []:
        if r.get("reason") == "access-to-specific-domain":
            desc = r.get("description") or ""
            # description shape: "Request access to the following domains: a, b, c"
            if ":" in desc:
                doms = desc.split(":", 1)[1].strip().rstrip(".")
                out.extend([d.strip() for d in doms.split(",") if d.strip()])
    return out


def has_recent_permission_change(rec: dict, days: int = 365) -> bool:
    """True if any permission was added (not removed) in the last N days."""
    history = rec.get("permissionChangeHistory") or []
    cutoff = datetime.now(timezone.utc).date()
    for entry in history:
        try:
            d = datetime.strptime(entry.get("date") or "", "%Y-%m-%d").date()
        except Exception:
            continue
        if (cutoff - d).days > days:
            continue
        changes = entry.get("changes") or {}
        for kind in ("permissions", "host_permissions"):
            if changes.get(kind, {}).get("added"):
                return True
    return False


def recent_permission_additions(rec: dict, days: int = 365) -> list[dict]:
    history = rec.get("permissionChangeHistory") or []
    cutoff = datetime.now(timezone.utc).date()
    out: list[dict] = []
    for entry in history:
        try:
            d = datetime.strptime(entry.get("date") or "", "%Y-%m-%d").date()
        except Exception:
            continue
        if (cutoff - d).days > days:
            continue
        changes = entry.get("changes") or {}
        added_perms = changes.get("permissions", {}).get("added", []) or []
        added_hosts = changes.get("host_permissions", {}).get("added", []) or []
        if added_perms or added_hosts:
            out.append({
                "date": entry.get("date"),
                "oldVersion": entry.get("oldVersion"),
                "added_permissions": added_perms,
                "added_host_permissions": added_hosts,
            })
    return out


def has_email_change(rec: dict) -> bool:
    return bool(rec.get("emailChangeHistory"))


def risk_score(rec: dict) -> float:
    """Combined heuristic risk = impact * likelihood (each 0-4, so 0-16)."""
    return float((rec.get("riskImpact") or 0)) * float((rec.get("riskLikelihood") or 0))


# ----------------------------------------------------------------------------
# Summary CSV
# ----------------------------------------------------------------------------

CSV_FIELDS = [
    "id", "name", "users", "rating", "rating_count",
    "category", "last_update",
    "risk_impact", "risk_likelihood", "risk_score",
    "linkedin_access", "linkedin_targeted_domains",
    "blocked", "unlisted",
    "recent_perm_change", "email_changes",
    "in_malicious_db", "malicious_db_reason",
]


def build_summary_csv(records: list[dict], malicious_db: dict[str, dict],
                      out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for rec in records:
            ext_id = rec.get("id") or ""
            mal = malicious_db.get(ext_id)
            w.writerow({
                "id": ext_id,
                "name": (rec.get("name") or "")[:80],
                "users": rec.get("userCount") or 0,
                "rating": rec.get("ratingValue") or "",
                "rating_count": rec.get("ratingCount") or 0,
                "category": rec.get("categoryLabel") or rec.get("category") or "",
                "last_update": rec.get("lastUpdate") or "",
                "risk_impact": rec.get("riskImpact") if rec.get("riskImpact") is not None else "",
                "risk_likelihood": rec.get("riskLikelihood") if rec.get("riskLikelihood") is not None else "",
                "risk_score": f"{risk_score(rec):.1f}",
                "linkedin_access": int(has_linkedin_access(rec)),
                "linkedin_targeted_domains": ";".join(linkedin_targeted_domains(rec)),
                "blocked": int(bool(rec.get("isTotalBlocked") or rec.get("isDownloadBlocked"))),
                "unlisted": int(bool(rec.get("isUnlisted"))),
                "recent_perm_change": int(has_recent_permission_change(rec)),
                "email_changes": len(rec.get("emailChangeHistory") or []),
                "in_malicious_db": int(bool(mal)),
                "malicious_db_reason": (mal or {}).get("reason", ""),
            })


# ----------------------------------------------------------------------------
# Markdown report
# ----------------------------------------------------------------------------

def build_report_md(records: list[dict], malicious_db: dict[str, dict],
                    out_path: Path, source_jsonl: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = len(records)
    if n == 0:
        out_path.write_text("# Chrome-Stats analysis\n\n_(no enriched records found)_\n")
        return

    with_data = [r for r in records if not r.get("_error")]
    n_with_data = len(with_data)

    # Risk distribution
    impact_counts = Counter(r.get("riskImpact") for r in with_data)
    likelihood_counts = Counter(r.get("riskLikelihood") for r in with_data)

    # LinkedIn-targeting
    linkedin_targets = [r for r in with_data if has_linkedin_access(r)]
    not_targeting_linkedin = n_with_data - len(linkedin_targets)

    # CWS status
    blocked = [r for r in with_data if r.get("isTotalBlocked") or r.get("isDownloadBlocked")]
    unlisted = [r for r in with_data if r.get("isUnlisted")]

    # Permission changes / email changes
    recent_perm = [r for r in with_data if has_recent_permission_change(r)]
    email_changes = [r for r in with_data if has_email_change(r)]

    # Top categories
    cat_counts = Counter(
        (r.get("categoryLabel") or r.get("category") or "").strip()
        for r in with_data
    )

    # Top-N highest risk
    by_score = sorted(with_data, key=risk_score, reverse=True)[:25]
    by_users = sorted(with_data, key=lambda r: -(r.get("userCount") or 0))[:25]

    # toborrm9 cross-reference
    in_db = [r for r in with_data if (r.get("id") or "") in malicious_db]

    L: list[str] = []
    L.append("# Chrome-Stats enrichment of LinkedIn's extension probe list")
    L.append("")
    L.append(
        f"Per-extension data pulled from the [Chrome-Stats](https://chrome-stats.com/) "
        f"API (Premium plan, 10k req/day) for each extension ID in "
        f"[`probed-extension-ids.txt`](../probed-extension-ids.txt)."
    )
    L.append("")
    L.append(f"**Source data:** [`{source_jsonl.relative_to(REPO_ROOT)}`](../{source_jsonl.relative_to(REPO_ROOT)}) (gitignored)")
    L.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    L.append("")
    L.append("## Coverage")
    L.append("")
    L.append("| | count |")
    L.append("|---|---|")
    L.append(f"| Records in JSONL | **{n:,}** |")
    L.append(f"| With usable Chrome-Stats data | **{n_with_data:,}** |")
    L.append(f"| Errored / not found | **{n - n_with_data:,}** |")
    L.append("")

    L.append("## Risk impact distribution (Chrome-Stats `riskImpact`)")
    L.append("")
    L.append("`riskImpact` is what the extension *can* do (capability), "
             "0 = none, 4 = maximum. This is independent of whether the "
             "extension is *actually* malicious — broad-permissions "
             "extensions like uBlock Origin score 4 here too.")
    L.append("")
    L.append("| impact | count | share |")
    L.append("|---|---|---|")
    for v in [0, 1, 2, 3, 4, None]:
        c = impact_counts.get(v, 0)
        L.append(f"| {v if v is not None else '(missing)'} | {c:,} | {100*c/max(n_with_data,1):.1f}% |")
    L.append("")

    L.append("## Risk likelihood distribution (Chrome-Stats `riskLikelihood`)")
    L.append("")
    L.append("`riskLikelihood` is what the extension is *believed* to do "
             "(intent), 0 = trusted, 4 = high suspicion. This is the "
             "more interesting number — it's where Chrome-Stats' opinion "
             "of the extension lives.")
    L.append("")
    L.append("| likelihood | count | share |")
    L.append("|---|---|---|")
    for v in [0, 1, 2, 3, 4, None]:
        c = likelihood_counts.get(v, 0)
        L.append(f"| {v if v is not None else '(missing)'} | {c:,} | {100*c/max(n_with_data,1):.1f}% |")
    L.append("")

    L.append("## LinkedIn-targeting share")
    L.append("")
    L.append(
        f"Of the {n_with_data:,} extensions LinkedIn fingerprints, "
        f"**{len(linkedin_targets):,}** ({100*len(linkedin_targets)/max(n_with_data,1):.1f}%) "
        f"explicitly request access to `linkedin.com` in their manifest "
        f"(per Chrome-Stats `riskImpactReasons`). The remaining "
        f"**{not_targeting_linkedin:,}** "
        f"({100*not_targeting_linkedin/max(n_with_data,1):.1f}%) have no "
        f"declared interest in LinkedIn — yet LinkedIn fingerprints them anyway."
    )
    L.append("")

    L.append("## CWS removal / unlisting status")
    L.append("")
    L.append("| status | count |")
    L.append("|---|---|")
    L.append(f"| Blocked from download (`isTotalBlocked` or `isDownloadBlocked`) | {len(blocked):,} |")
    L.append(f"| Unlisted from CWS search (`isUnlisted`) | {len(unlisted):,} |")
    L.append("")

    L.append("## Update-poisoning indicators")
    L.append("")
    L.append(
        f"**{len(recent_perm):,}** extensions added at least one permission "
        f"or host-permission in the last 365 days "
        f"(per `permissionChangeHistory`). Adding permissions in an update "
        f"is the standard mechanism for the update-poisoning attack — "
        f"benign extension ships, gains user base, then 'just one more "
        f"permission' update extracts data."
    )
    L.append("")
    L.append(
        f"**{len(email_changes):,}** extensions have at least one author-email "
        f"change recorded (per `emailChangeHistory`). Email changes are "
        f"the standard fingerprint of the **acquisition-then-poisoning** "
        f"attack: a popular legitimate extension is sold to a new owner, "
        f"who then ships a malicious update."
    )
    L.append("")

    L.append("## Top categories")
    L.append("")
    L.append("| category | count |")
    L.append("|---|---|")
    for cat, count in cat_counts.most_common(15):
        L.append(f"| {cat or '(blank)'} | {count:,} |")
    L.append("")

    L.append("## Highest-risk extensions (top 25 by `impact × likelihood`)")
    L.append("")
    L.append("| ID | Name | Users | Impact | Likelihood | Targets LinkedIn? |")
    L.append("|---|---|---|---|---|---|")
    for r in by_score:
        targets = "yes" if has_linkedin_access(r) else ""
        users = r.get("userCount")
        users_str = f"{users:,}" if isinstance(users, int) else "?"
        L.append(
            f"| `{r.get('id','')}` | {(r.get('name') or '')[:42]} | "
            f"{users_str} | {r.get('riskImpact')} | "
            f"{r.get('riskLikelihood')} | {targets} |"
        )
    L.append("")

    L.append("## Most-installed extensions LinkedIn probes for (top 25)")
    L.append("")
    L.append("| Name | Users | Risk (impact × likelihood) |")
    L.append("|---|---|---|")
    for r in by_users:
        users = r.get("userCount") or 0
        L.append(
            f"| {(r.get('name') or '')[:60]} | {users:,} | "
            f"{r.get('riskImpact')} × {r.get('riskLikelihood')} = {risk_score(r):.0f} |"
        )
    L.append("")

    L.append("## Cross-reference with toborrm9/malicious_extension_sentry")
    L.append("")
    L.append(
        f"Of the {n_with_data:,} enriched records, **{len(in_db):,}** are also "
        f"in the curated malicious-extension database. Combined with "
        f"Chrome-Stats' own risk model:"
    )
    L.append("")
    if in_db:
        L.append("| ID | Name | Chrome-Stats impact × likelihood | toborrm9 reason |")
        L.append("|---|---|---|---|")
        for r in sorted(in_db, key=risk_score, reverse=True):
            ext_id = r.get("id") or ""
            mal = malicious_db.get(ext_id, {})
            L.append(
                f"| `{ext_id}` | {(r.get('name') or '')[:38]} | "
                f"{r.get('riskImpact')} × {r.get('riskLikelihood')} | "
                f"{mal.get('reason') or ''} |"
            )
    L.append("")

    out_path.write_text("\n".join(L))


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_IN)
    p.add_argument("--csv", type=Path, default=SUMMARY_CSV)
    p.add_argument("--report", type=Path, default=REPORT_MD)
    args = p.parse_args()

    records = load_jsonl(args.in_path)
    print(f"[+] loaded {len(records):,} records from {args.in_path.relative_to(REPO_ROOT)}",
          file=sys.stderr)

    malicious_db = load_malicious_db(MALICIOUS_SNAPSHOT)
    if malicious_db:
        print(f"[+] loaded malicious DB ({len(malicious_db):,} IDs)", file=sys.stderr)
    else:
        print("[!] no malicious-DB snapshot at "
              f"{MALICIOUS_SNAPSHOT.relative_to(REPO_ROOT)} — "
              "run cross_reference_malicious.py first",
              file=sys.stderr)

    build_summary_csv(records, malicious_db, args.csv)
    print(f"[+] wrote {args.csv.relative_to(REPO_ROOT)}", file=sys.stderr)

    build_report_md(records, malicious_db, args.report, args.in_path)
    print(f"[+] wrote {args.report.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
