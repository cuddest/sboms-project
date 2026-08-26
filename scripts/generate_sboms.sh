#!/usr/bin/env bash
# Generate CycloneDX SBOMs for every repository in REPOS_DIR using Syft.
#
# Usage: ./scripts/generate_sboms.sh [REPOS_DIR] [OUT_DIR]
#   REPOS_DIR defaults to repos/
#   OUT_DIR   defaults to sboms/

set -euo pipefail

REPOS_DIR="${1:-repos}"
OUT_DIR="${2:-sboms}"

mkdir -p "$OUT_DIR"

for repo in "$REPOS_DIR"/*/; do
    name="$(basename "$repo")"
    [ -d "$repo" ] || continue

    echo "===== Generating SBOM for $name ====="

    syft "dir:$repo" \
        -o "cyclonedx-json=$OUT_DIR/$name.json"
done
