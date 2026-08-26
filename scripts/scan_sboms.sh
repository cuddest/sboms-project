#!/usr/bin/env bash
# Scan every SBOM in sboms/ with Grype and store JSON reports in scans/.
#
# Usage: ./scripts/scan_sboms.sh

set -euo pipefail

mkdir -p scans

for sbom in sboms/*.json; do
    name="$(basename "$sbom" .json)"

    echo "===== Scanning $name ====="

    grype "sbom:$sbom" \
        -o json > "scans/${name}.json"
done
