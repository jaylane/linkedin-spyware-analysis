# → CRXray has moved

The CRXray design proposal originally drafted here has graduated to its own repository:

→ **<https://github.com/jaylane/CRXray.io>**

The canonical proposal now lives at [`docs/PROPOSAL.md`](https://github.com/jaylane/CRXray.io/blob/main/docs/PROPOSAL.md) in that repo. The landing-page [`README.md`](https://github.com/jaylane/CRXray.io/blob/main/README.md) summarises the project.

## Why this stub still exists

CRXray was conceived during this LinkedIn extension-fingerprinting audit, when the search for a freely-available cross-reference dataset surfaced the broader gap: every public extension-risk-scoring service has been retired or migrated behind enterprise paywalls. That observation is documented in [`reports/MALICIOUS_OVERLAP.md`](../reports/MALICIOUS_OVERLAP.md) and motivated the CRXray project.

The Phase-1 working code (Chrome-Stats client + analysis driver) still lives in this repository — see [`scripts/chrome_stats_client.py`](../scripts/chrome_stats_client.py) and [`scripts/analyze_chrome_stats.py`](../scripts/analyze_chrome_stats.py) — because they are the pipeline that produced this audit's findings ([`reports/CHROME_STATS_ANALYSIS.md`](../reports/CHROME_STATS_ANALYSIS.md)). They will graduate to the CRXray repository once that project's architecture is firm enough to host them.

This stub is left in place so that the historical link from this audit's commit history to the CRXray project remains intact.
