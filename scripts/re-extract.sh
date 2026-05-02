#!/usr/bin/env bash
#
# re-extract.sh
#
# Regenerate `probed-extension-ids.txt` from a freshly-downloaded LinkedIn
# webpack chunk. The chunk that contains the AbuseFeaturesCollectionCoordinator
# module has a content-hashed filename that changes across deploys, but the
# probe list always uses the same shape:
#
#     [{id:"<32-char-id>",file:"..."}, ...]
#
# This script greps that pattern out of any file you point it at and writes
# the deduplicated, sorted list of extension IDs to stdout (or to
# probed-extension-ids.txt if --write is passed).
#
# Usage:
#   ./scripts/re-extract.sh <path-to-chunk.js>
#   ./scripts/re-extract.sh <path-to-chunk.js> --write
#
# How to find the right chunk:
#   1. Open linkedin.com in Chrome with DevTools open.
#   2. Network tab. Reload.
#   3. In the filter box, type:  chrome-extension://
#   4. Right-click the resulting JS file → "Save as..." (or copy URL and curl).
#   5. Run this script against that file.
#
# Robustness:
#   - Works on minified or beautified bundles.
#   - Tolerates either `id:"..."` (minified) or `"id": "..."` (pretty) shapes.
#   - Validates that each extracted string is exactly 32 lowercase a-p chars
#     (Chrome extension IDs are base16-of-public-key, so they are restricted
#     to a-p, never digits, exactly 32 chars).
#   - Does not require Node, Python, or jq — only POSIX grep / sort / awk.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <path-to-chunk.js> [--write]" >&2
    exit 64
fi

CHUNK="$1"
WRITE_MODE="${2:-}"

if [[ ! -f "$CHUNK" ]]; then
    echo "error: $CHUNK not found" >&2
    exit 66
fi

EXTRACTED=$(
    grep -oE '"?id"?[[:space:]]*:[[:space:]]*"[a-p]{32}"' "$CHUNK" \
    | grep -oE '[a-p]{32}' \
    | sort -u
)

COUNT=$(printf '%s\n' "$EXTRACTED" | grep -c . || true)

if [[ "$COUNT" -lt 100 ]]; then
    echo "warning: only $COUNT extension IDs found — is this the right chunk?" >&2
    echo "(expected several thousand; the AbuseFeaturesCollectionCoordinator" >&2
    echo "module lives in whichever chunk also contains 'AedEvent' and" >&2
    echo "'SpectroscopyEvent'. Try grepping for those strings to find it.)" >&2
fi

if [[ "$WRITE_MODE" == "--write" ]]; then
    OUT="$(dirname "$0")/../probed-extension-ids.txt"
    printf '%s\n' "$EXTRACTED" > "$OUT"
    echo "wrote $COUNT IDs to $OUT" >&2
else
    printf '%s\n' "$EXTRACTED"
    echo "extracted $COUNT IDs" >&2
fi
