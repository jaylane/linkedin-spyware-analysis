# Thanks

This repository builds on prior work and observations by other people. They
deserve credit. Listed roughly in the order their contributions surfaced.

## Reporters

- **`u/bluesky1433`** — original poster of the [r/linkedin thread](https://www.reddit.com/r/linkedin/comments/1qwsmjg/linkedin_continuous_console_errors_on_google/) that first surfaced the
  flood of `chrome-extension://invalid/ net::ERR_FAILED` errors in DevTools
  consoles. Their methodical troubleshooting (clear cookies, disable
  extensions, fresh Chrome profile, incognito, switch to Firefox) ruled out
  every user-side cause and made it obvious the requests had to be coming
  from linkedin.com itself. The thread also drew LinkedIn's only public
  acknowledgement of the behaviour.

- **The other commenters in that thread** — multiple users independently
  confirmed the same behaviour across Chrome, Edge, Opera, and Brave;
  pointed out that Firefox is silent (which we now know is because the
  probe is gated to `userAgent.indexOf("Chrome") > -1`); and identified
  the relevant code lines in the chunk well before this writeup existed.

## Independent analysis

- **The author of [browsergate.eu/how-it-works](https://browsergate.eu/how-it-works/)** — independent
  technical writeup of the same behaviour.

- **The OP of [r/europe 1sdw2ac](https://www.reddit.com/r/europe/comments/1sdw2ac/linkedin_scanned_6222_browser_extensions_on_every/)**
  ("LinkedIn scanned 6222 browser extensions on every…") — independently
  arrived at the same **6,222** unique-ID figure documented here.

## Workarounds

- **[`@mujtaba3b`](https://github.com/mujtaba3b)** — published a Chrome
  extension that intercepts and blocks the probe locally. Useful immediate
  harm-reduction for users who don't want to switch to Firefox while
  waiting for LinkedIn to fix this.

## Frame of reference

- **LinkedIn's own engineers**, indirectly — the readability of the
  deobfuscated module owes a lot to LinkedIn's choice to keep meaningful
  identifiers in the export list (`AbuseFeaturesCollectionCoordinator`,
  `fireExtensionDetectedEvents`, `fireSpectroscopyEvent`,
  `dnaTopLevelFlatKeyEncodingMap`, etc.). Without those names, this
  writeup would have taken substantially longer.

---

If you contributed to this conversation publicly and aren't listed here,
that's an oversight, not an omission. Open a PR adding yourself, or open
an issue and I'll add you.
