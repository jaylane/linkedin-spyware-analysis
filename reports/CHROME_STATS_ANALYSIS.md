# Chrome-Stats enrichment of LinkedIn's extension probe list

Per-extension data pulled from the [Chrome-Stats](https://chrome-stats.com/) API (Premium plan, 10,000 req/day) for each of the **6,222 unique** Chrome extensions in [`probed-extension-ids.txt`](../probed-extension-ids.txt) that LinkedIn fingerprints on every Chromium pageview.

**Source data:** [`data/chrome-stats-detail.jsonl`](../data/chrome-stats-detail.jsonl) (gitignored — regenerable)
**Generated:** 2026-05-02 10:02 UTC

## Executive summary

Of the **6,220** extensions LinkedIn fingerprints (per Chrome-Stats data):

- **36.2%** (2,249) explicitly request access to `linkedin.com` in their manifest. The framing of "anti-abuse against LinkedIn-targeting extensions" applies to *this slice only*.
- **63.8%** (3,971) do **not** declare any access to `linkedin.com`. LinkedIn fingerprints them on every pageview anyway.
- **10.5%** (656) have Chrome-Stats `riskLikelihood >= 3` — i.e., elevated suspicion of actual misuse (as opposed to merely-broad permissions).
- **22.9%** (1,423) added at least one permission or host-permission in the last year (the **update-poisoning** signal).
- **7.6%** (471) had at least one author-email change in their lifetime (the **acquisition-then-poisoning** signal).
- **0.05%** (3) are currently blocked or unlisted by the Chrome Web Store.
- **0.64%** (40) appear in the curated [`toborrm9/malicious_extension_sentry`](https://github.com/toborrm9/malicious_extension_sentry) database. (See [`MALICIOUS_OVERLAP.md`](MALICIOUS_OVERLAP.md) for the categorical breakdown.)

## Coverage

| | count |
|---|---|
| Records in JSONL | **6,222** |
| With usable Chrome-Stats data | **6,220** |
| Errored / not found | **2** |

## Risk impact distribution (Chrome-Stats `riskImpact`)

`riskImpact` is what the extension *can* do (capability), 0 = none, 4 = maximum. This is independent of whether the extension is *actually* malicious — broad-permissions extensions like uBlock Origin score 4 here too.

| impact | count | share |
|---|---|---|
| 0 | 248 | 4.0% |
| 1 | 854 | 13.7% |
| 2 | 2,001 | 32.2% |
| 3 | 2,381 | 38.3% |
| 4 | 736 | 11.8% |
| (missing) | 0 | 0.0% |

## Risk likelihood distribution (Chrome-Stats `riskLikelihood`)

`riskLikelihood` is what the extension is *believed* to do (intent), 0 = trusted, 4 = high suspicion. This is the more interesting number — it's where Chrome-Stats' opinion of the extension lives.

| likelihood | count | share |
|---|---|---|
| 0 | 367 | 5.9% |
| 1 | 1,365 | 21.9% |
| 2 | 3,832 | 61.6% |
| 3 | 616 | 9.9% |
| 4 | 40 | 0.6% |
| (missing) | 0 | 0.0% |

## LinkedIn-targeting share

Of the 6,220 extensions LinkedIn fingerprints, **2,249** (36.2%) explicitly request access to `linkedin.com` in their manifest (per Chrome-Stats `riskImpactReasons`). The remaining **3,971** (63.8%) have no declared interest in LinkedIn — yet LinkedIn fingerprints them anyway.

### Risk distribution: LinkedIn-targeting subset vs everything else

If anti-abuse were the goal, we'd expect the LinkedIn-targeting subset to skew higher-likelihood (more known-suspicious extensions). Compare:

| likelihood | LinkedIn-targeting | non-targeting |
|---|---|---|
| 0 | 71 (3.2%) | 296 (7.5%) |
| 1 | 405 (18.0%) | 960 (24.2%) |
| 2 | 1,456 (64.7%) | 2,376 (59.8%) |
| 3 | 298 (13.3%) | 318 (8.0%) |
| 4 | 19 (0.8%) | 21 (0.5%) |

### Top non-LinkedIn domains LinkedIn-probed extensions also touch

Each row is a domain (apex form) that ≥1 LinkedIn-probed extension declares access to. Reveals what other targets / data flows the probed extensions are designed for. (`linkedin.com` and `licdn.com` excluded as they are by definition the framing of this analysis.)

| domain | extensions touching it |
|---|---|
| `google.com` | 531 |
| `localhost` | 457 |
| `googleapis.com` | 243 |
| `x.com` | 242 |
| `twitter.com` | 242 |
| `facebook.com` | 210 |
| `indeed.com` | 200 |
| `instagram.com` | 175 |
| `openai.com` | 166 |
| `youtube.com` | 133 |
| `supabase.co` | 120 |
| `glassdoor.com` | 112 |
| `reddit.com` | 98 |
| `vercel.app` | 88 |
| `tiktok.com` | 81 |
| `microsoft.com` | 77 |
| `zoom.us` | 75 |
| `greenhouse.io` | 74 |
| `gstatic.com` | 73 |
| `co.uk` | 67 |
| `ziprecruiter.com` | 66 |
| `force.com` | 66 |
| `salesforce.com` | 65 |
| `lever.co` | 65 |
| `monster.com` | 63 |
| `0.1` | 61 |
| `hubspot.com` | 60 |
| `amazonaws.com` | 58 |
| `github.com` | 58 |
| `whatsapp.com` | 57 |

## CWS removal / unlisting status

| status | count |
|---|---|
| Blocked from download (`isTotalBlocked` or `isDownloadBlocked`) | 3 |
| Unlisted from CWS search (`isUnlisted`) | 228 |

## Update-poisoning indicators

**1,423** extensions added at least one permission or host-permission in the last 365 days (per `permissionChangeHistory`). Adding permissions in an update is the standard mechanism for the update-poisoning attack — benign extension ships, gains user base, then 'just one more permission' update extracts data.

**471** extensions have at least one author-email change recorded (per `emailChangeHistory`). Email changes are the standard fingerprint of the **acquisition-then-poisoning** attack: a popular legitimate extension is sold to a new owner, who then ships a malicious update.

## Top categories

| category | count |
|---|---|
| Tools | 2,477 |
| Workflow & Planning | 1,953 |
| Social Networking | 640 |
| productivity/communication | 467 |
| Developer Tools | 214 |
| Education | 115 |
| Functionality & UI | 70 |
| Accessibility | 56 |
| Just for Fun | 50 |
| Well-being | 43 |
| Privacy & Security | 39 |
| Shopping | 36 |
| Entertainment | 17 |
| News & Weather | 14 |
| Art & Design | 10 |

## Highest-risk extensions (top 25 by `impact × likelihood`)

| ID | Name | Users | Impact | Likelihood | Targets LinkedIn? |
|---|---|---|---|---|---|
| `amblopokdajebnmbjcfdhgmncdgnhdem` | Socivo Assist | 1 | 4 | 4 | yes |
| `bbdaefobemkclkaadfladeijcmeddblj` | Writesmartx | 27 | 4 | 4 | yes |
| `dclfgfnoipdggiphclodokadmdaaapeo` | Otimizador de Currículo (IA) – Focado em A | 11 | 4 | 4 | yes |
| `capgbfgnklakdedfbjkacmjpkebanifk` | Acedit | 3,000 | 4 | 3 | yes |
| `aagiojdphcbpafnpcniokdjcpfdphjgk` | Salesforce Prism | 10 | 4 | 3 | yes |
| `adcgjaalckbeikpdpiacnjamfihalkmc` | Deen Shield - Islamic Productivity Tool | 11 | 4 | 3 | yes |
| `aeddihecploomdndlodecnopbeckjnmo` | Quiply | ? | 4 | 3 | yes |
| `ahjbffbpifndaagokhldcaalpegbhpkd` | Profile Enhancer Pro | 1 | 4 | 3 | yes |
| `ajeffabgdodbbdngakbpafbggnoegdjd` | WellShared-AI | 2 | 4 | 3 | yes |
| `ajmafehbfjamoglibfgjffajcpepdbam` | RapidStart LinkedIn Capture | 6 | 4 | 3 | yes |
| `ajoickdlofadbaooambnlnlbcpdnkkck` | ChatGPT, Bing & Bard For Chrome: Kursor | 306 | 4 | 3 | yes |
| `aljkfodiamdmgkpkonndmldemdihbbfm` | Bragbooq | 5 | 4 | 3 | yes |
| `amhkgjfekhegmofpnkdnmfcjgckndbfc` | Charles - EU Digital Sovereignty | 516 | 4 | 3 | yes |
| `bbhmahnocajljlaeibidfmdnhlnkboob` | writi.io: GPT-4 Writing for LinkedIn | 6,000 | 4 | 3 | yes |
| `bemigakfboklbahldndagnfoiejfdaio` | Channel Ascent | 2 | 4 | 3 | yes |
| `bfaaodgddkchepnmbefgohmkjmoagcdm` | MagicOffer Job Apply Helper | ? | 3 | 4 |  |
| `bfchakhfjhimdlehkpdeaafpedbhndja` | WorkGo AI Autofill Assistant | 6 | 4 | 3 | yes |
| `bhoaipnlbnpbedecmkmfaopipbjipcfm` | Business Golfer's Network | 5 | 4 | 3 | yes |
| `binfkcmklghbjkbiaknecnheepdiagfl` | RecruitBPM | 78 | 4 | 3 | yes |
| `ceincnackpbffbakcafjjgnehlfhefne` | Pathable - AI Copilot for X | 1 | 3 | 4 |  |
| `cgekhbhgoiinffledgpopabbdancibcn` | Engagi - AI for social media engagement | 578 | 4 | 3 | yes |
| `cgikbmpjlipafepacaajlmgdjffgikig` | LI Email Finder (100% FREE) & Group Scrape | 1,361 | 3 | 4 | yes |
| `clbhclemafomoiepfcnakdnidmjohcpn` | Cleve - Save Social Content | 6 | 4 | 3 | yes |
| `dbcllnegglfpapjcfhfndakmajhhbdfd` | LeadGenius - Auto Connect Tool | 1,156 | 3 | 4 | yes |
| `dbkagbdbogiggfankjpgknndkkgkplnb` | Intentional Browsing | 2 | 4 | 3 | yes |

## Most-installed extensions LinkedIn probes for (top 25)

| Name | Users | Risk (impact × likelihood) |
|---|---|---|
| Adobe Acrobat: PDF edit, convert, sign tools | 335,000,000 | 4 × 1 = 4 |
| Grammarly: AI Writing Assistant and Grammar Checker App | 42,000,000 | 3 × 0 = 0 |
| Malwarebytes Browser Guard | 11,000,000 | 3 × 0 = 0 |
| Loom – Screen Recorder & Screen Capture | 8,000,000 | 4 × 0 = 0 |
| QuillBot: AI Writing and Grammar Checker Tool | 6,000,000 | 2 × 0 = 0 |
| Sider: Chat with all AI: GPT-5, Claude, DeepSeek, Gemini, Gr | 5,000,000 | 3 × 0 = 0 |
| DeepL: translate and write with AI | 4,000,000 | 3 × 0 = 0 |
| Ad Blocker: Stands AdBlocker | 3,000,000 | 3 × 0 = 0 |
| AI Grammar Checker & Paraphraser – LanguageTool | 3,000,000 | 2 × 0 = 0 |
| Pop up blocker for Chrome™ - Poper Blocker | 2,000,000 | 3 × 0 = 0 |
| Microsoft Editor: Spelling & Grammar Checker | 2,000,000 | 2 × 0 = 0 |
| Apollo.io: Free B2B Phone Number & Email Finder | 1,000,000 | 3 × 0 = 0 |
| Chat with all AI models (Gemini, Claude, DeepSeek…) & AI Age | 1,000,000 | 3 × 2 = 6 |
| Merlin - Ask AI to Research, Write & Review | 1,000,000 | 4 × 0 = 0 |
| Social Stream Ninja | 1,000,000 | 4 × 2 = 8 |
| Scribbr Citation Generator | 1,000,000 | 3 × 0 = 0 |
| Content Ninja Suggest | 1,000,000 | 3 × 2 = 6 |
| Ninja Connect | 1,000,000 | 4 × 2 = 8 |
| HubSpot Sales | 1,000,000 | 3 × 0 = 0 |
| Scribe: AI Documentation, SOPs & Screenshots | 1,000,000 | 3 × 0 = 0 |
| SBlock - Super Ad Blocker | 900,000 | 2 × 1 = 2 |
| Boomerang for Gmail | 900,000 | 2 × 0 = 0 |
| Allow Copy + | 700,000 | 2 × 0 = 0 |
| Calendly: Meeting Scheduling Software | 700,000 | 2 × 0 = 0 |
| PIXM Phishing Protection | 700,000 | 4 × 1 = 4 |

## Author concentration

The 6,222 extensions are produced by **5,198** distinct authors. **262** authors produced 2 or more extensions on the list. This is a useful concentration signal — if a small number of authors are producing a large share of LinkedIn-probed extensions, that points at organised lead-gen vendors / tooling shops more than independent maintainers.

### Top 20 authors by number of LinkedIn-probed extensions

| Author | Extension count |
|---|---|
| My Most Trusted Network | 20 |
| MMT Network | 18 |
| Sellframe Ltd | 18 |
| Sellframe Ltd | 12 |
| scrapdatapro.com | 11 |
| Adslibrary.ai | 7 |
| Devsource | 7 |
| Adslibrary.ai | 6 |
| upstaff Ltd | 6 |
| Logical Pure Minds SRL | 6 |
| Social Attache Software Corporation | 5 |
| pjw | 5 |
| Wealides Fintech Private Limited | 5 |
| patrickoliver2653 | 4 |
| lempire | 4 |
| Better Context | 4 |
| PINPINSOFT-WANGKAN-13818154078 | 4 |
| 深圳市小满科技有限公司 | 4 |
| English In Games | 4 |
| Jens.Marketing | 4 |

## Cross-reference with toborrm9/malicious_extension_sentry

Of the 6,220 enriched records, **40** are also in the curated malicious-extension database. Combined with Chrome-Stats' own risk model:

| ID | Name | Chrome-Stats impact × likelihood | toborrm9 reason |
|---|---|---|---|
| `bkpgbmjmifkbonccfmpejokfndolikcj` | Highperformr AI - Phone Number and Ema | 4 × 2 | Policy Violation |
| `aciamgifeoagmcojlibbdhoabolgdopo` | PN CoPilot | 4 × 2 | Policy Violation |
| `gfcligffighgnnfljcamdhgppbgfjddb` | Boostawaa - Social Media Management | 4 × 2 | Policy Violation |
| `nlllhibclkoddmfaljpifkfhabmkjjpk` | Reacheazy | 3 × 2 | Policy Violation |
| `gdldfceehpabhcehoglbnfgkdpgnnelo` | Leadspicker | 3 × 2 | Policy Violation |
| `lgknneiodddmfbbpaklighafdocbfnme` | Email Finder by Scalelist | 3 × 2 | Policy Violation |
| `achcinfieogfidhjekdbbmapmffifchl` | Warmr | 3 × 2 | Policy Violation |
| `jbbanajdakjmholbhekdkcfekhibilhg` | SalesMind AI | 3 × 2 | Policy Violation |
| `kfihpeckbnofhbnaeeoilcokaaphpcfa` | Email & Phone Finder - LeadLoft | 3 × 2 | Policy Violation |
| `amomdmnemaieioenimcelcagpdbdbigi` | Leadseeder 2.0 | 3 × 2 | Policy Violation |
| `cafbjepckpmnmlliiheacibehokblihc` | NavWise: Prospect List Exporter | 3 × 2 | Policy Violation |
| `dcllajlpjeaobemjcplencinnjdkefkc` | Queens Game Solver | 3 × 2 | Policy Violation |
| `eckfhhngfhepmndojbnphnlnemglmojp` | Valley | 3 × 2 | Policy Violation |
| `fbmgcejhoneccecnplfllgkfgheoengm` | Buska LinkedIn | 3 × 2 | Policy Violation |
| `gmigkpkjegnpmjpmnmgnkhmoinpgdnfc` | Calendly Docket Free Meeting Schedul | 2 × 3 | Malware |
| `inloipbahbmhelpokmejailbmcegccal` | ConnectGenie - Linkedin AI Assistant | 3 × 2 | Policy Violation |
| `kdmcdkanhnbdcmadgljmhdimdlfpgple` | Saywhat | 3 × 2 | Policy Violation |
| `kjidkkncdchjnnfpclneimlcmghcfoon` | intentleads - Engagement based LinkedI | 3 × 2 | In store but not whitelisted |
| `ldaebepnkfockfedaloedoelkjlmpnnl` | Yadulink - LinkedIn Prospecting Assist | 3 × 2 | Policy Violation |
| `mjhocphphjjjcabfdcaemfkokegeebbg` | TikTok Leads | 3 × 2 | Policy Violation |
| `nbcbdidccniaiigpdiocldgggfeagbog` | ReactIn | 3 × 2 | Policy Violation |
| `nippdajkmjpnpnajkafoadeopbjdffjo` | Viewelo | 2 × 3 | Policy Violation |
| `pobknfocgoijjmokmhimkfhemcnigdji` | EventSphere | 3 × 2 | Malware |
| `ailnbbigginhlppdboejnjhcmldkolio` | LinkedIn Cookie importer for Derrick | 2 × 2 | Policy Violation |
| `bgkijgmoikigljbbfokahemdnhilkkma` | Shield - LinkedIn Analytics | 2 × 2 | Policy Violation |
| `cghdjcdmopohjlogglcbocjldjhjlddg` | BizWik | 2 × 2 | Policy Violation |
| `dgncekenlgnneibllkjinpcfccajpjmc` | LinkedIn Queens Solver | 2 × 2 | Policy Violation |
| `kojhnafkiednagnljfgakalcbfbklbdk` | Kondo | 2 × 2 | Policy Violation |
| `oedechpcnjolalnpghbibmadgfjgaopm` | NxtJob AI Profile Optimization & Job T | 3 × 1 | Policy Violation |
| `fbbjijdngocdplimineplmdllhjkaece` | ChatGPT for Chrome - Search AI | 3 × 1 | Policy Violation |
| `bhhdblckjkgijhjajngmjdijpmhoeobp` | InContact - Contact Book for LinkedIn | 3 × 1 | Policy Violation |
| `dfpbcakpogbfaohnnjlgghdjkgaoiaik` | Taplio X | 3 × 1 | Policy Violation |
| `imhlnhlbiencamnbpigopiibddajimep` | LeadContact-Phone Number & Email Finde | 3 × 1 | Policy Violation |
| `icgdnaedamjhnmnomlhkifmkjkijnibb` | ReplyMind | 2 × 1 | Policy Violation |
| `lfnlgdmddmiidbnaeiibmlbadefcnjhi` | LinkInNova.ai | 2 × 1 | Policy Violation |
| `ebhomdageggjbmomenipfbhcjamfkmbl` | Zoomcoder Extension | 1 × 1 | Policy Violation |
| `pkghgkfjhjghinikeanecbgjehojfhdg` | ﻿InterAlt | 0 × 2 | Malware |
| `agleiimpggapjekcdhdjbmegjbbkleie` | Ground News - Bias Checker | 2 × 0 | In store but Suspicious |
| `cplhlgabfijoiabgkigdafklbhhdkahj` | Vidnoz Flex - Video recorder & Video s | 3 × 0 | In store but Suspicious |
| `fnpejdoiggdgagmdfmkllgfpagjgjfoi` | Gemini AI Assistance | 0 × 2 | Policy Violation |
