# LinkedIn extension-fingerprinting analysis

Source: `ceg6yuxj06s98drqjyvgw3yzi.js` — a 2.7 MB webpack chunk (`chunk.585.167fa9d3f6f67606cd3e.js`) loaded from `static.licdn.com` on every linkedin.com page.

This file is **not** a separately-injected script. It is one chunk of LinkedIn's main web client, served sitewide. The relevant module begins at module ID `9269` of webpack chunk `585`, with the active probe at line ~9571 of the deminified file.

## TL;DR — what it does

Two complementary techniques to enumerate which Chrome extensions a visitor has installed, plus a full classical browser fingerprint, all sent to LinkedIn's tracking pipeline.

### 1. Active probe — `AedEvent` (Anti-abuse Extension Detection)
- Iterates a hardcoded list of **6,236 entries** (**6,222 unique** Chrome extension IDs — the bundle contains 14 duplicate entries), each paired with a known-public file from that extension's `web_accessible_resources` manifest declaration.
- For each pair, calls `fetch("chrome-extension://<id>/<file>")`.
- Under Manifest V3 the fetch only succeeds if the extension is installed *and* the file is exposed — so a successful response confirms installation.
- Successes are POSTed to LinkedIn's tracking endpoint as event `AedEvent` with `browserExtensionIds: [...]`.
- Has a `staggerDetectionMs` mode that spaces probes out, and a `requestIdleCallback` mode that hides the work in idle frames.

### 2. Passive scan — `SpectroscopyEvent`
- Recursively walks the entire DOM — every text node, every attribute on every element — looking for any string containing `chrome-extension://`.
- Many extensions inject icon URLs, iframes, content-script artefacts, or `data-*` attributes that contain their own ID. This catches them passively, including extensions **not on the hardcoded list**.
- Emitted as event `SpectroscopyEvent` with `browserExtensionIds: [...]`.

### 3. Surrounding `AbuseFeaturesCollectionCoordinator` (same module)
The extension probes ride alongside a full device-fingerprint collection that gathers:

- `userAgent`, `appName/Version/CodeName`, `navigator.platform`, `cpuClass`, `hardwareConcurrency`, `deviceMemory`, `doNotTrack`, `webdriver`
- screen w/h, avail w/h, `colorDepth`, `pixelDepth`, `devicePixelRatio`, `screen.orientation`
- `navigator.language` (and userLanguage/browserLanguage/systemLanguage), `Intl` timezone, `Date().getTimezoneOffset()`
- `navigator.getBattery()` → `{charging, level, chargingTime, dischargingTime}`
- `navigator.connection` → `{saveData, effectiveType, rtt, downlink, downlinkMax, type}`
- touch support → `{touchStart, touchEvent, maxTouchPoints}`
- `navigator.mediaDevices.enumerateDevices()` → labels of every camera, microphone and speaker
- WebRTC ICE-candidate probe
- canvas fingerprint (`canvasHash`, `canvasWinding`)
- WebGL fingerprint — renderer, vendor, antialiasing, ~30 shader-precision parameters
- AudioContext fingerprint (sum of samples 4500–5000 of an OfflineAudioContext render)
- enumerated font list + `fontsHash`
- `navigator.plugins`
- spoofing/consistency checks: `liedOS`, `liedBrowser`, `liedResolution`, `liedLanguages`, `adBlockInstalled`
- storage availability: `sessionStorage`, `localStorage`, `indexedDB`, `openDatabase`, `addBehavior`
- the PerimeterX (HUMAN Security) bot-defense cookies `_px3`, `_pxhd`, `_pxvid`, `pxcts` are read and re-emitted

Everything is LZ-string compressed and base64'd via the bundle's `compressToBase64`, then encoded by `encodeDNA` / `encodeDFPIos` / `encodeDFPAndroid` before being shipped through `globalThis.triggerApfc` / `globalThis.triggerDnaApfcEventOnDemandVersioned` to LinkedIn's standard Voyager tracking endpoint.

## Files in this folder

| file | what it is |
|---|---|
| [`deobfuscated-extension-detection.js`](deobfuscated-extension-detection.js) | The two extension-detection functions + DOM walker, fully renamed and beautified, ready to read or quote. |
| [`probed-extension-ids.txt`](probed-extension-ids.txt) | All 6,222 unique extension IDs from the hardcoded probe list, one per line, sorted. Look any of them up at `https://chromewebstore.google.com/detail/<id>`. |
| [`screenshots/`](screenshots/) | DevTools captures showing the probes firing on a real linkedin.com pageview. |
| [`scripts/re-extract.sh`](scripts/re-extract.sh) | Regenerates `probed-extension-ids.txt` from a freshly-downloaded chunk. Use this to track changes across LinkedIn deploys. |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-capture record of the bundle hash, probe count, and any changes. PRs welcome with newer captures. |
| [`THANKS.md`](THANKS.md) | Credits to the people who reported this before me. |
| [`reports/MALICIOUS_OVERLAP.md`](reports/MALICIOUS_OVERLAP.md) | Cross-reference of LinkedIn's 6,222-entry probe list against an independent malicious-extension database. **Headline: 0.64% overlap.** |
| [`reports/CHROME_STATS_ANALYSIS.md`](reports/CHROME_STATS_ANALYSIS.md) | Per-extension risk analysis using Chrome-Stats Premium data: capability × intent risk distribution, LinkedIn-targeting share, update-poisoning indicators, ownership-transfer indicators. |
| [`scripts/cross_reference_malicious.py`](scripts/cross_reference_malicious.py) | Regenerates the malicious-overlap cross-reference. Standard-library Python, no deps. |
| [`scripts/chrome_stats_client.py`](scripts/chrome_stats_client.py) | Thin stdlib-only client for the [Chrome-Stats](https://chrome-stats.com/) API. Bulk-fetch mode is resumable and JSONL-cached. |
| [`scripts/analyze_chrome_stats.py`](scripts/analyze_chrome_stats.py) | Turns the JSONL output of `chrome_stats_client.py` into a CSV summary and a Markdown findings report. |
| [`scripts/fetch_extension_metadata.py`](scripts/fetch_extension_metadata.py) | Earlier no-API CWS scraper. Useful as a free-tier fallback for extensions Chrome-Stats lacks. |
| [`docs/CRXRAY_PROPOSAL.md`](docs/CRXRAY_PROPOSAL.md) | Design proposal for a free, open-data extension-risk-scoring layer (project name **CRXray**) that this analysis surfaced the need for. |
| `README.md` | This file. |

## Observed in the wild

I stumbled into this while trying to grab a resized version of my own LinkedIn profile image (`linkedin.com/in/jayjlane.png?size=100`). The image URL errored out, so I went back to my main profile page — and with DevTools already open, I noticed the Network panel filling up with thousands of failed `chrome-extension://invalid/` fetches in two bursts (one near page-load, one a few seconds later — corresponding to the two code paths in `fireExtensionDetectedEvents`: the eager call, and the `requestIdleCallback`/route-change re-fire).

Thinking one of my own extensions was misbehaving, I disabled the usual suspects — uBlock Origin, Obsidian Web Clipper, React DevTools — and the errors kept coming. I went scorched earth and disabled *every* extension. Still happening. That's what made me look deeper, and the deeper I looked, the clearer it became that the requests were coming from linkedin.com itself.

![DevTools Network panel showing chrome-extension://invalid/ probes on a single profile pageview](screenshots/devtools-network-overview.png)

The detail view of any single row shows it was a `fetch` that failed with `net::ERR_FAILED` — the diagnostic Chrome returns when a `chrome-extension://` URL targets an extension that isn't installed:

![Closer view: each row is a failed fetch with type=fetch, status=(failed) net::ERR_FAILED](screenshots/devtools-network-failed-fetches.png)

Important presentation detail: Chrome's DevTools rewrites the displayed URL to **`chrome-extension://invalid/`** when the target extension isn't installed. This is a Chrome-side privacy mitigation — it deliberately hides which extension ID was probed so a screenshot can't leak the probe list. The real fetches go to `chrome-extension://<actual-id>/<file>` for each of the 6,222 unique IDs in [`probed-extension-ids.txt`](probed-extension-ids.txt).

In one captured session: **300 of the 2,865 visible network requests on a single profile pageview were extension probes** (scrolled view, the actual count is in the thousands — there is one fetch per probed ID).

## Is the probe list actually targeting malicious extensions?

LinkedIn frames the probe internally as **anti-abuse telemetry** (the class is literally `AbuseFeaturesCollectionCoordinator`). A natural empirical question is: how much of the 6,222-entry probe list overlaps with extensions that an *independent* curated database has classified as malicious, suspicious, or policy-violating?

Cross-referencing against [`toborrm9/malicious_extension_sentry`](https://github.com/toborrm9/malicious_extension_sentry) (1,465 unique IDs at snapshot time):

| metric | value |
|---|---|
| LinkedIn probe list (unique IDs) | **6,222** |
| Malicious DB (unique IDs) | **1,465** |
| **Overlap** | **40** |
| Overlap as % of LinkedIn probe list | **0.64%** |
| Probes targeting extensions with **no** known-malicious classification | **6,182 (99.36%)** |

So two things are simultaneously true:

1. **Where the lists overlap, the framing holds.** The 40 matched extensions are overwhelmingly LinkedIn-specific scraping / prospecting / lead-gen / fake-engagement tools (e.g. *Linkedin Cookie Importer*, *Shield Linkedin Analytics*, *NavWise: Prospect List Exporter*, *Salesmind Ai*, *ConnectGenie - Linkedin AI Assistant*, *Yadulink Linkedin Prospec*, *Buska LinkedIn*, *Highperformr Ai Phone Num*). For that narrow slice, "anti-abuse" is a defensible label.

2. **But that's 0.64%.** The other 99.36% of the IDs LinkedIn fingerprints on every Chromium pageview have **no** classification in the curated malicious-extension database. Whatever LinkedIn is doing with those 6,182 probes, "checking for known-malicious extensions" is not a complete explanation.

Full breakdown, the 40-row overlap table, and reproduction instructions: [`reports/MALICIOUS_OVERLAP.md`](reports/MALICIOUS_OVERLAP.md).

## This is not new — LinkedIn was told over two months ago

The behaviour documented here is not something I (or anyone else doing this analysis) discovered first. It has been visibly broken in users' DevTools consoles for **months**, and LinkedIn's own support team has publicly acknowledged it as a "known issue" while shipping no fix.

**Original report (r/linkedin, ~2026-02):** [LinkedIn Continuous console errors on Google Chrome](https://www.reddit.com/r/linkedin/comments/1qwsmjg/linkedin_continuous_console_errors_on_google/)

A user noticed their browser console flooding with hundreds of:

```
GET chrome-extension://invalid/   net::ERR_FAILED
```

errors per minute on every linkedin.com page. They tried clearing cookies, removing all extensions, switching to a fresh Chrome profile, and going incognito. None of it worked, because the requests were being made by linkedin.com itself, not by any extension on the user's machine. Firefox didn't show the errors — because, as we now know, the probe is gated to Chromium-only via a `navigator.userAgent.indexOf("Chrome")` check.

**LinkedIn's official response in the same thread, from `u/LinkedInHelpTeam`:**

> "Hi, sorry this took a bit of time. We confirmed that this is a known issue, and we're currently working on a fix. Thanks so much for your patience."

That response is more than two months old as of this writing. **The probe is still firing.** You can verify that yourself in 30 seconds with the steps in the next section.

**Related r/europe crosspost** ([1sdw2ac](https://www.reddit.com/r/europe/comments/1sdw2ac/linkedin_scanned_6222_browser_extensions_on_every/)) titled *"LinkedIn scanned 6222 browser extensions on every…"* — independently arriving at exactly the **6,222** unique-ID figure documented in this repository.

**Independent writeup:** [browsergate.eu/how-it-works](https://browsergate.eu/how-it-works/) describes the same technique.

**Community workaround:** another commenter (`@mujtaba3b` on GitHub) shipped a Chrome extension that intercepts and blocks the probe locally. Useful as immediate harm-reduction, but obviously not a substitute for LinkedIn fixing it on their end.

So to be clear about the timeline:

| date | what happened |
|---|---|
| ≈ 2026-02 | Users start seeing hundreds of failed `chrome-extension://invalid/` fetches per pageview in the console. |
| ≈ 2026-02 | Multiple bug reports filed publicly on Reddit. |
| ≈ 2026-02 | `u/LinkedInHelpTeam` publicly confirms it as a "known issue" being "worked on". |
| 2026-05-02 | Probe is still firing on every linkedin.com pageview, with the same 6,222-entry hardcoded list. This repository was created. |

What that timeline implies is up to the reader. Two readings are possible:

1. **Incompetence** — LinkedIn agrees it's a bug and simply has not prioritised the fix in 2+ months.
2. **Deliberate** — the "known issue, working on a fix" line is the standard PR holding pattern for telemetry that the company has no intention of removing, because the probe is functioning exactly as designed (it is named `AbuseFeaturesCollectionCoordinator` after all).

The code itself does not adjudicate between those two readings. But "shipping a 6,222-entry browser-extension-fingerprinting probe to every visitor in a specific browser family" is not something that lands in production by accident, and a console error visible to anyone with DevTools open is not something a company of LinkedIn's size fails to notice for two months unless it chooses to.

## Reproducing the find yourself

1. Open linkedin.com in Chrome with DevTools open.
2. **Network** tab → Fetch/XHR filter. Reload. You will see thousands of red `chrome-extension://invalid/` rows — one per probed extension that you don't have installed.
3. To see the source: **Network** tab → search `chunk.585` → open the response → search for `chrome-extension://`. You will land in the same module.
4. Or, in the **Sources** panel, set an XHR/fetch breakpoint on the substring `chrome-extension://`. Reload; you will hit the breakpoint inside `fetchExtensions` once for each probe.
5. To watch the exfil event: **Network** tab → filter `li/track`, look for the POST whose body decodes to an `AedEvent` containing `browserExtensionIds`.

## Caveats / fairness

- The module name is `AbuseFeaturesCollectionCoordinator`. LinkedIn's framing internally is anti-fraud / anti-scraping rather than ad-targeting. That said, "anti-abuse" telemetry that fingerprints every visitor and enumerates 6,236 specific extensions is still extension-fingerprinting, regardless of intent.
- The fetch trick relies on Manifest V3 `web_accessible_resources`. Extension authors who don't declare any web-accessible files are not detectable by technique #1; they may still be detectable by technique #2 if they inject anything into the DOM.
- The probe only fires in Chromium (`navigator.userAgent` contains `"Chrome"`). Firefox and Safari users are not probed by this module.
- The PerimeterX cookies are PerimeterX's, not LinkedIn's; they are observed here, not minted here.
- This analysis is a snapshot. The chunk hash (`167fa9d3f6f67606cd3e`) and the probed-ID list change across deploys.

## License of analysis

The deobfuscated file in this folder is a clean-room renaming of LinkedIn's minified output for the purpose of security research and public-interest commentary. The original code is © LinkedIn / Microsoft.
