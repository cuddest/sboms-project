#!/usr/bin/env python3

import csv
import json
from pathlib import Path

SCANS_DIR = Path("scans")
OUTPUT = Path("results/vulnerabilities.csv")


def first_or_empty(values):
    if isinstance(values, list) and values:
        return values[0]
    return ""


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    for scan_file in sorted(SCANS_DIR.glob("*.json")):
        repository = scan_file.stem

        with scan_file.open("r", encoding="utf-8") as f:
            report = json.load(f)

        for match in report.get("matches", []):
            artifact = match.get("artifact", {})
            vulnerability = match.get("vulnerability", {})
            fix = vulnerability.get("fix", {})

            rows.append(
                {
                    "repository": repository,
                    "package": artifact.get("name", ""),
                    "installed_version": artifact.get("version", ""),
                    "vulnerability_id": vulnerability.get("id", ""),
                    "severity": vulnerability.get("severity", ""),
                    "fixed_version": first_or_empty(fix.get("versions", [])),
                    "dependency_type": artifact.get("type", ""),
                }
            )

    fieldnames = [
        "repository",
        "package",
        "installed_version",
        "vulnerability_id",
        "severity",
        "fixed_version",
        "dependency_type",
    ]

    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} vulnerability findings to {OUTPUT}")


if __name__ == "__main__":
    main()
