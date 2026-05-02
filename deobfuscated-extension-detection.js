/*
 * ========================================================================
 *  LinkedIn browser-extension-detection module — deobfuscated
 * ========================================================================
 *
 *  Source file:  ceg6yuxj06s98drqjyvgw3yzi.js
 *                (LinkedIn webpack chunk 585, served from
 *                 static.licdn.com on every linkedin.com page load)
 *  Original location:  module 9269 of the chunk, lines ~9571-9590
 *
 *  Webpack module export list (verbatim from the bundle):
 *      AbuseFeaturesCollectionCoordinator
 *      CommonFeaturesAccessor
 *      EXTENSION_PREFIX
 *      compressToBase64
 *      dfpAndroidFeaturesKeyEncodingMap
 *      dfpAndroidTopLevelKeyEncodingMap
 *      dfpIosFeaturesKeyEncodingMap
 *      dfpIosPayloadKeysEncodingMap
 *      dnaTopLevelFlatKeyEncodingMap
 *      dnaTopLevelNestedKeyEncodingMap
 *      encodeDFPAndroid
 *      encodeDFPIos
 *      encodeDNA
 *      fetchExtensions               <-- active extension probe
 *      fireExtensionDetectedEvents   <-- active probe + exfil
 *      fireSpectroscopyEvent         <-- DOM-scan exfil
 *      getDocument
 *      isBrowser
 *      isUserAgentChrome
 *      parseFoundString
 *      scanDOMForPrefix              <-- passive DOM scan
 *
 *  Naming key (LinkedIn’s internal abbreviations, inferred from symbols):
 *      APFC  = Abuse Prevention Feature Collection
 *      AFC   = AbuseFeaturesCollection
 *      DFP   = Device FingerPrint  (parallel iOS / Android collectors)
 *      DNA   = the web variant of the same fingerprint payload
 *      AED   = Anti-abuse Extension Detection
 *      Spectroscopy = passive DOM scan for chrome-extension:// URLs
 *
 *  Below is the original code, beautified, with identifiers renamed and
 *  the obfuscated control-flow tightened. Behaviour is unchanged.
 * ------------------------------------------------------------------------
 */


// --- 1. The hardcoded probe list ----------------------------------------
//
// 6,236 entries. Each is a Chrome extension ID paired with one file from
// that extension's `web_accessible_resources` declaration. Because
// Manifest V3 only allows web pages to fetch() a chrome-extension://
// URL when the extension explicitly exposes the file, a successful fetch
// proves the extension is installed. A failed fetch proves nothing.
//
// The full list is in ./probed-extension-ids.txt (one ID per line).
const EXTENSION_PROBES = [
    { id: "aaaeoelkococjpgngfokhbkkfiiegolp", file: "assets/index-COXueBxP.js" },
    { id: "aabfjmnamlihmlicgeoogldnfaaklfon", file: "images/logo.svg"        },
    { id: "aacbpggdjcblgnmgjgpkpddliddineni", file: "sidebar.html"           },
    // ... 6,233 more entries ...
    { id: "ppppdkjdnjpomdkpamemnhcebkbpbcma", file: "content.styles.css"     },
];


// --- 2. Environment guards ----------------------------------------------

function isBrowser() {
    // Skip server-side rendering passes.
    return typeof window !== "undefined"
        && window
        && window.appEnvironment !== "node";
}

function isUserAgentChrome() {
    // The chrome-extension:// fetch trick only works in Chromium browsers.
    // Firefox uses moz-extension:// and Safari blocks the technique entirely,
    // so this code only fires for Chrome / Edge / Brave / Opera / Arc / etc.
    return window?.navigator?.userAgent?.indexOf("Chrome") > -1;
}


// --- 3. Active extension probe ------------------------------------------
//
// fetchExtensions() — fires every probe in parallel.
async function fetchExtensions() {
    const detected = [];

    const fetches = EXTENSION_PROBES.map(({ id, file }) =>
        fetch(`chrome-extension://${id}/${file}`)
    );

    const results = await Promise.allSettled(fetches);

    results.forEach((result, idx) => {
        if (result.status === "fulfilled" && result.value !== undefined) {
            detected.push(EXTENSION_PROBES[idx].id);
        }
    });

    return detected;          // array of extension IDs that are installed
}


// fetchExtensionsStaggered() — same probe, but spaced out in time so the
// burst is harder to spot in DevTools / extension-side network logs.
async function fetchExtensionsStaggered(delayMs) {
    const detected = [];

    for (const { id, file } of EXTENSION_PROBES) {
        try {
            if (await fetch(`chrome-extension://${id}/${file}`)) {
                detected.push(id);
            }
        } catch (_) { /* swallow — failure means "not installed" */ }

        if (delayMs > 0) {
            await new Promise(r => setTimeout(r, delayMs));
        }
    }
    return detected;
}


// fireExtensionDetectedEvents() — top-level orchestrator.
// Calls one of the probes above, then ships the list of detected
// extension IDs to LinkedIn's tracking pipeline as an "AedEvent".
async function fireExtensionDetectedEvents(tracker, extraPayload = {}, opts = {}) {
    if (!isBrowser() || !isUserAgentChrome()) return;

    const {
        useRequestIdleCallback = false,
        timeout                = 2000,
        staggerDetectionMs     = 0,
    } = opts;

    const run = async () => {
        const ids = staggerDetectionMs > 0
            ? await fetchExtensionsStaggered(staggerDetectionMs)
            : await fetchExtensions();

        if (Array.isArray(ids) && ids.length > 0) {
            // Sent to LinkedIn's standard Voyager/EventBus tracking endpoint.
            tracker.fireTrackingPayload("AedEvent", {
                browserExtensionIds: ids,
                ...extraPayload,
            });
        }
    };

    if (useRequestIdleCallback && typeof window.requestIdleCallback === "function") {
        // Hide the work in idle frames so it doesn't show up in
        // PerformanceObserver long-task reports.
        window.requestIdleCallback(run, { timeout });
    } else {
        await run();
    }
}


// --- 4. Passive DOM scan ("Spectroscopy") --------------------------------
//
// Many extensions inject elements with attributes like
//     <img src="chrome-extension://<id>/icon.png">
// or stylesheets / iframes / data-* attributes containing the prefix.
// This walker recursively scans the entire DOM (every text node + every
// attribute on every element) looking for the substring "chrome-extension://"
// and parses out the 32-char extension ID.

const EXTENSION_PREFIX = "chrome-extension://";

function getDocument() {
    return window.document;
}

function parseFoundString(s) {
    const i = s.indexOf(EXTENSION_PREFIX);
    if (i === -1) return "";
    return s.substring(i + EXTENSION_PREFIX.length).split("/")[0];
}

function scanDOMForPrefix(node, needle, hits) {
    if (node.nodeType === Node.TEXT_NODE
        && node.textContent !== undefined
        && node.textContent.includes(needle)) {
        hits.push(parseFoundString(node.textContent));
    }

    if (node.nodeType === Node.ELEMENT_NODE) {
        for (let i = 0; i < node.attributes.length; i++) {
            const a = node.attributes.item(i);
            if (a.value !== undefined && a.value.includes(needle)) {
                hits.push(parseFoundString(a.value));
            }
        }
    }

    for (let i = 0; i < node.childNodes.length; i++) {
        scanDOMForPrefix(node.childNodes[i], needle, hits);
    }
}

function fireSpectroscopyEvent(tracker, extraPayload = {}) {
    if (!isBrowser() || !isUserAgentChrome()) return;

    const hits = [];
    scanDOMForPrefix(getDocument(), EXTENSION_PREFIX, hits);

    if (Array.isArray(hits) && hits.length > 0) {
        tracker.fireTrackingPayload("SpectroscopyEvent", {
            browserExtensionIds: hits,     // raw IDs leaked by the extensions themselves
            ...extraPayload,
        });
    }
}


// --- 5. The wider data-collection envelope -------------------------------
//
// AedEvent / SpectroscopyEvent are NOT the only thing this module exports.
// The same chunk also defines `AbuseFeaturesCollectionCoordinator`, which
// runs a classic browser-fingerprint sweep and ships it via the same
// pipeline (globalThis.triggerApfc / globalThis.triggerDnaApfcEventOnDemandVersioned).
// Inventory of fields collected (from the obfuscated `components` array
// at line ~2260 / 4520 / 9319 of the bundle):
//
//   Hardware / OS:
//     userAgent, appName, appVersion, appCodeName, navigator.platform,
//     cpuClass, hardwareConcurrency, deviceMemory, doNotTrack, webdriver
//
//   Display:
//     screen width/height, availWidth/availHeight,
//     colorDepth, pixelDepth, devicePixelRatio,
//     screen.orientation
//
//   Locale / time:
//     navigator.language (+ userLanguage/browserLanguage/systemLanguage),
//     Intl.DateTimeFormat().resolvedOptions().timeZone,
//     Date().getTimezoneOffset()
//
//   Device sensors / inputs:
//     navigator.getBattery() -> { charging, level, chargingTime, dischargingTime }
//     navigator.connection   -> { saveData, effectiveType, rtt, downlink, downlinkMax, type }
//     touchSupport           -> { touchStart, touchEvent, maxTouchPoints }
//
//   Media devices:
//     navigator.mediaDevices.enumerateDevices()
//     -> for each device:  { label, groupId, deviceId, kind }
//        (i.e. labels of every camera / microphone / speaker)
//     WebRTC ICE-candidate probe
//
//   Browser-storage availability flags:
//     sessionStorage, localStorage, indexedDB, openDatabase, addBehavior
//
//   GPU / rendering fingerprints:
//     canvas hash + winding rule (canvas fingerprint)
//     WebGL: renderer, vendor, antialiasing, dozens of shader-precision
//             ranges, max-texture-size, etc.
//     AudioContext fingerprint (slice 4500–5000 of an OfflineAudioContext
//                                renderedBuffer, summed)
//
//   Spoofing / consistency checks ("lied*"):
//     liedOS, liedBrowser, liedResolution, liedLanguages, adBlockInstalled
//
//   Fonts:
//     enumerated font list + fontsHash
//
//   Plugins:
//     navigator.plugins -> { type, description, suffixes }
//
//   Cookies (PerimeterX bot-defense state):
//     reads/writes _px3, _pxhd, _pxvid, pxcts via window message bridge
//     (line ~9551). PerimeterX (now HUMAN Security) is the third-party
//     anti-bot vendor LinkedIn uses; this module observes its cookies
//     and re-emits them through LinkedIn's own pipeline.
//
//   Extension surface (this file):
//     - 6,236 actively-probed extension IDs   -> AedEvent
//     - any chrome-extension:// URL leaked into the DOM -> SpectroscopyEvent
//
// All of the above is encoded via `encodeDNA` / `encodeDFPIos` /
// `encodeDFPAndroid`, base64-compressed via `compressToBase64`
// (LZ-string), and POSTed as the body of the standard LinkedIn tracking
// endpoint.
//
// ------------------------------------------------------------------------
// End of deobfuscation.
