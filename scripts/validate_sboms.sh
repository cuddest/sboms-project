#!/usr/bin/env bash
# Validate generated JSON artifacts.
#
# A file passes only if it is non-empty AND contains valid JSON.
# This catches the zero-byte failure mode seen during the experiment,
# where "jq empty" alone succeeds on empty input.

set -euo pipefail

fail=0

for dir in sboms scans; do
    for f in "$dir"/*.json; do
        [ -e "$f" ] || continue
        if [ ! -s "$f" ]; then
            echo "EMPTY:    $f"
            fail=1
        elif ! jq -e . "$f" > /dev/null 2>&1; then
            echo "INVALID:  $f"
            fail=1
        fi
    done
done

if [ "$fail" -eq 0 ]; then
    echo "All SBOM and scan files are non-empty valid JSON."
else
    exit 1
fi
