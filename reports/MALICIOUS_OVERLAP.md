# Cross-reference: LinkedIn probes ∩ malicious-extension database

How much of LinkedIn's 6,222-entry extension probe list overlaps with extensions that have been independently classified as malicious, suspicious, or policy-violating?

## Sources

- **LinkedIn probe list:** [`probed-extension-ids.txt`](../probed-extension-ids.txt) (6,222 unique IDs) — extracted from the LinkedIn web client bundle. See [`README.md`](../README.md) for capture details.
- **Malicious DB:** [`toborrm9/malicious_extension_sentry`](https://github.com/toborrm9/malicious_extension_sentry) (1,465 unique IDs in `malicious_extensions_detailed.csv` at snapshot time). Categories: Malware, Policy Violation, Bundling Unwanted Software, In store but Suspicious, In store but not whitelisted, Removal reason Unknown, etc.
- **Snapshot taken:** 2026-05-02 08:25 UTC (local copy at [`data/malicious-db-snapshot.csv`](../data/malicious-db-snapshot.csv)).

## Headline numbers

| metric | value |
|---|---|
| LinkedIn probe list (unique IDs) | **6,222** |
| Malicious DB (unique IDs) | **1,465** |
| **Overlap** (in BOTH lists) | **40** |
| Overlap as % of LinkedIn probe list | **0.64%** |
| Overlap as % of malicious DB | **2.73%** |
| Probes targeting extensions with **no** known-malicious classification | **6,182** (99.36%) |

## Two readings of the same numbers

**Reading A — narrowly defensible.** When LinkedIn's probe list does intersect the malicious DB, the matched extensions are overwhelmingly tools whose stated purpose is to scrape, automate, or otherwise abuse LinkedIn itself (cookie importers, prospecting / lead-gen extensions, Sales Navigator scrapers, fake-engagement tools). For that narrow slice, "anti-abuse telemetry" is a defensible framing.

**Reading B — what the bulk of the list is doing.** That defensible slice is **0.64% of the probe list**. The other **99.36%** of the extensions LinkedIn fingerprints on every Chromium pageview have **no** classification in a curated malicious-extension database. Whatever LinkedIn is doing with those 6,182 probes, "checking for known-malicious extensions" is not a complete explanation.

Both readings are simultaneously true, and that is the most interesting thing about the dataset.

## Overlap breakdown by malicious-DB reason

| reason | count |
|---|---|
| Policy Violation | 34 |
| Malware | 3 |
| In store but Suspicious | 2 |
| In store but not whitelisted | 1 |

## Full overlap

Each row is an extension that appears on **both** LinkedIn's hardcoded probe list and the toborrm9 malicious-extension database at snapshot time. Look any ID up at `https://chromewebstore.google.com/detail/<id>` (returns 404 if delisted).

| ID | Name | Reason | DB source | Added |
|---|---|---|---|---|
| `agleiimpggapjekcdhdjbmegjbbkleie` | Ground News - Bias Checker | In store but Suspicious | Store Monitoring | 2026-02-23 |
| `cplhlgabfijoiabgkigdafklbhhdkahj` | Vidnoz Flex - Video recorder &amp; Video share | In store but Suspicious | https://www.esentire.com/security-advisories/update-malicious-chrome-extension-campaign | 2025-01-08 |
| `kjidkkncdchjnnfpclneimlcmghcfoon` | intentleads - Engagement based LinkedIn Leads PREVIEW | In store but not whitelisted | Store Monitoring | 2026-02-08 |
| `gmigkpkjegnpmjpmnmgnkhmoinpgdnfc` | Calendly Docket \| Free Meeting Scheduling Software | Malware | https://layerxsecurity.com/blog/layerx-reveals-40malicious-browser-extensions/ | 2025-05-22 |
| `pobknfocgoijjmokmhimkfhemcnigdji` | EventSphere | Malware | https://layerxsecurity.com/blog/layerx-reveals-40malicious-browser-extensions/ | 2025-05-22 |
| `pkghgkfjhjghinikeanecbgjehojfhdg` | ﻿Interalt | Malware | https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2 | 2026-04-14 |
| `cghdjcdmopohjlogglcbocjldjhjlddg` | BizWik | Policy Violation | Store Monitoring | 2026-04-07 |
| `gfcligffighgnnfljcamdhgppbgfjddb` | Boostawaa Social Media Ma | Policy Violation | Store Monitoring | 2026-04-01 |
| `fbmgcejhoneccecnplfllgkfgheoengm` | Buska LinkedIn | Policy Violation | Store Monitoring | 2026-04-07 |
| `fbbjijdngocdplimineplmdllhjkaece` | Chatgpt For Chrome Search | Policy Violation | Store Monitoring | 2026-04-18 |
| `inloipbahbmhelpokmejailbmcegccal` | ConnectGenie - Linkedin AI Assistant | Policy Violation | Store Monitoring | 2026-03-20 |
| `lgknneiodddmfbbpaklighafdocbfnme` | Email Finder By Scalelist | Policy Violation | Store Monitoring | 2026-04-16 |
| `kfihpeckbnofhbnaeeoilcokaaphpcfa` | Email Phone Finder Leadlo | Policy Violation | Store Monitoring | 2026-04-13 |
| `fnpejdoiggdgagmdfmkllgfpagjgjfoi` | Gemini Ai Assistance | Policy Violation | Store Monitoring | 2026-04-13 |
| `bkpgbmjmifkbonccfmpejokfndolikcj` | Highperformr Ai Phone Num | Policy Violation | Store Monitoring | 2026-04-13 |
| `bhhdblckjkgijhjajngmjdijpmhoeobp` | Incontact Contact Book Fo | Policy Violation | Store Monitoring | 2026-04-13 |
| `kojhnafkiednagnljfgakalcbfbklbdk` | Kondo | Policy Violation | Store Monitoring | 2026-03-11 |
| `imhlnhlbiencamnbpigopiibddajimep` | Leadcontact Phone Number | Policy Violation | Store Monitoring | 2026-03-05 |
| `amomdmnemaieioenimcelcagpdbdbigi` | Leadseeder 20 | Policy Violation | Store Monitoring | 2026-04-13 |
| `gdldfceehpabhcehoglbnfgkdpgnnelo` | Leadspicker | Policy Violation | Store Monitoring | 2026-04-22 |
| `ailnbbigginhlppdboejnjhcmldkolio` | Linkedin Cookie Importer | Policy Violation | Store Monitoring | 2026-04-13 |
| `dgncekenlgnneibllkjinpcfccajpjmc` | LinkedIn Queens Solver | Policy Violation | Store Monitoring | 2026-03-19 |
| `lfnlgdmddmiidbnaeiibmlbadefcnjhi` | Linkinnovaai | Policy Violation | Store Monitoring | 2026-04-02 |
| `cafbjepckpmnmlliiheacibehokblihc` | NavWise: Prospect List Exporter | Policy Violation | Store Monitoring | 2026-04-06 |
| `oedechpcnjolalnpghbibmadgfjgaopm` | Nxtjob Ai Profile Optimiz | Policy Violation | Store Monitoring | 2026-04-13 |
| `ebhomdageggjbmomenipfbhcjamfkmbl` | Photo Downloader for Facebook, Instagram, + | Policy Violation | https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers | 2026-02-10 |
| `aciamgifeoagmcojlibbdhoabolgdopo` | Pn Copilot | Policy Violation | Store Monitoring | 2026-04-02 |
| `dcllajlpjeaobemjcplencinnjdkefkc` | Queens Game Solver | Policy Violation | Store Monitoring | 2026-03-30 |
| `nlllhibclkoddmfaljpifkfhabmkjjpk` | Reacheazy | Policy Violation | Store Monitoring | 2026-04-13 |
| `nbcbdidccniaiigpdiocldgggfeagbog` | Reactin | Policy Violation | Store Monitoring | 2026-03-05 |
| `icgdnaedamjhnmnomlhkifmkjkijnibb` | Replymind | Policy Violation | Store Monitoring | 2026-04-11 |
| `jbbanajdakjmholbhekdkcfekhibilhg` | Salesmind Ai | Policy Violation | Store Monitoring | 2026-04-13 |
| `kdmcdkanhnbdcmadgljmhdimdlfpgple` | Saywhat | Policy Violation | Store Monitoring | 2026-04-13 |
| `bgkijgmoikigljbbfokahemdnhilkkma` | Shield Linkedin Analytics | Policy Violation | Store Monitoring | 2026-04-07 |
| `dfpbcakpogbfaohnnjlgghdjkgaoiaik` | Taplio X | Policy Violation | Store Monitoring | 2026-04-06 |
| `mjhocphphjjjcabfdcaemfkokegeebbg` | TikTok Leads | Policy Violation | Store Monitoring | 2026-04-07 |
| `eckfhhngfhepmndojbnphnlnemglmojp` | Valley | Policy Violation | Store Monitoring | 2026-04-13 |
| `nippdajkmjpnpnajkafoadeopbjdffjo` | Viewelo | Policy Violation | Store Monitoring | 2026-04-04 |
| `achcinfieogfidhjekdbbmapmffifchl` | Warmr | Policy Violation | Store Monitoring | 2026-04-26 |
| `ldaebepnkfockfedaloedoelkjlmpnnl` | Yadulink Linkedin Prospec | Policy Violation | Store Monitoring | 2026-04-13 |

## Other databases considered

For transparency, here is what was checked and why it ended up not contributing.

### `wayfair-incubator/malicious-chrome-extension-scanner`

Suggested as a candidate cross-reference target. Investigated and rejected:

- **It is not a database.** Reviewing the source confirms it is a Python pipeline that ingests installed-extension inventory from Tenable (a corporate vulnerability scanner; plugins `96533` for Windows and `133180` for macOS are used to enumerate extensions on employee workstations) and forwards each `<extension_id>/<version>` to CrXcavator's risk-scoring API. No hardcoded list of malicious IDs lives in the repository.
- **CrXcavator (the actual scorer) is sunset.** `crxcavator.io` no longer resolves in DNS. The free service Duo Security operated for community extension risk scoring was retired by Cisco. The Wayfair repo's last commit was July 2020 (pre–Manifest V3), so it cannot run end-to-end today even with valid Tenable credentials.

Verdict: *no list to compare against*. The negative result is captured here so the next person checking can save the cycles.

### Other public sources

There is no other curated open dataset with the breadth and accessibility of `toborrm9/malicious_extension_sentry` that this repository is aware of as of the snapshot date. PRs adding additional cross-references are welcome — particularly anything that publishes a machine-readable CSV/JSON of confirmed-malicious or policy-violating extensions.

## Reproduce

```bash
python3 scripts/cross_reference_malicious.py
```

The script downloads the latest malicious-DB CSV at run time and regenerates this report. Snapshots are saved to `data/` so the comparison is reproducible even if upstream changes.
