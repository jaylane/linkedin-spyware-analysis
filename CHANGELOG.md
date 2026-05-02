# Changelog

This repository tracks LinkedIn's in-browser extension fingerprinting over
time. The bundle that contains the `AbuseFeaturesCollectionCoordinator`
module has a content-hashed filename (e.g. `chunk.585.<hash>.js`), and the
list of probed extensions changes across deploys.

Each entry below records:

- **Captured at:** when the bundle was downloaded (UTC).
- **Chunk filename:** the content-hashed filename as served from `static.licdn.com`.
- **Probe count:** total `{id, file}` entries in the hardcoded list, and
  the unique-ID count after deduplication.
- **Notes:** anything noteworthy that changed.

If you have an older or newer capture, PRs adding entries here (with a copy
of the chunk in a per-version folder, or just an updated `probed-extension-ids.txt`)
are welcome.

---

## 2026-05-02 — initial capture

- **Captured at:** 2026-05-02 ~07:54 UTC (00:54 PT)
- **Chunk filename:** `ceg6yuxj06s98drqjyvgw3yzi.js`
  (the file LinkedIn served on this date; webpack chunk `585`,
  inner build hash `167fa9d3f6f67606cd3e`)
- **Probe count:** **6,236** raw entries / **6,222** unique extension IDs
  (14 duplicates in the bundle — see "Duplicates" below)
- **Module location:** module `9269` of chunk `585`, line ~9571 of the
  deminified file
- **Module exports observed:** `AbuseFeaturesCollectionCoordinator`,
  `CommonFeaturesAccessor`, `EXTENSION_PREFIX`, `compressToBase64`,
  `dfpAndroidFeaturesKeyEncodingMap`, `dfpAndroidTopLevelKeyEncodingMap`,
  `dfpIosFeaturesKeyEncodingMap`, `dfpIosPayloadKeysEncodingMap`,
  `dnaTopLevelFlatKeyEncodingMap`, `dnaTopLevelNestedKeyEncodingMap`,
  `encodeDFPAndroid`, `encodeDFPIos`, `encodeDNA`, `fetchExtensions`,
  `fireExtensionDetectedEvents`, `fireSpectroscopyEvent`, `getDocument`,
  `isBrowser`, `isUserAgentChrome`, `parseFoundString`, `scanDOMForPrefix`
- **Tracking events observed:** `AedEvent` (active probe results),
  `SpectroscopyEvent` (passive DOM-scan results)
- **PerimeterX integration:** module reads/writes `_px3`, `_pxhd`,
  `_pxvid`, `pxcts` cookies and proxies them through a `window.postMessage`
  bridge (line ~9551)
- **Browsers targeted:** Chromium only (`navigator.userAgent` must contain
  the literal substring `"Chrome"`); Firefox and Safari users are not
  probed by this module
- **Duplicates:** 14 extra entries form 10 duplicated IDs:
  `aikafmmimkegennccplalihclachjfbb`,
  `apfehfekdjcfdcgckdibppehdfoblcnj`,
  `apnakbnhdheikelmoobdemadapbblgne`,
  `bfchakhfjhimdlehkpdeaafpedbhndja`,
  `deeolcegogcoggcpnpmacnojfccamehe`,
  `djmfklahpcmoleknenpemcgdbhllklij`,
  `galjpoldmaegeoidpdmimmdkmememcnb`,
  `gmlbpljlkpcjlphifmkjhnjbfelfiffj`,
  `hhlhmbmlempfdgijjkodlmnghefamnod`,
  `ndcimkancadipbckcncmiamcfhgmoagh`
  (some appear 2×, some 3×). Likely a build-pipeline merge artifact rather
  than intentional weighting.
