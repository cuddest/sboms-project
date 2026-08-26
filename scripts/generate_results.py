#!/usr/bin/env python3
"""Recompute the derived result artifacts from the raw experiment data.

Regenerates:
    results/sbom_summary.csv    component counts from the CycloneDX SBOMs
    results/baseline_stats.txt  package-level baseline and sample statistics

Usage: python3 scripts/generate_results.py   (run from the repository root)
"""

import csv
import json
from collections import Counter
from pathlib import Path

REPOSITORIES = [
    "CantusDB",
    "CoPeP",
    "cycode-cli",
    "openhands",
    "openpiv-python",
    "pypi-browser",
    "seed",
    "validator",
]

SBOMS_DIR = Path("sboms")
SCANS_DIR = Path("scans")
RESULTS_DIR = Path("results")


def write_sbom_summary():
    rows = []
    total = 0

    for name in REPOSITORIES:
        sbom_path = SBOMS_DIR / f"{name}.json"
        with sbom_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        count = len(data.get("components", []))
        total += count
        rows.append({"repository": name, "component_count": count})

    summary_path = RESULTS_DIR / "sbom_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["repository", "component_count"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {summary_path} ({len(rows)} repositories, {total} components total)")


def write_baseline_stats():
    lines = []
    lines.append("===== Package-Level Vulnerability Baseline =====")

    findings = []
    per_repo_sev = {}
    for scan_file in sorted(SCANS_DIR.glob("*.json")):
        repository = scan_file.stem
        with scan_file.open("r", encoding="utf-8") as f:
            report = json.load(f)
        for match in report.get("matches", []):
            severity = match.get("vulnerability", {}).get("severity", "Unknown")
            not_fixed = not match.get("vulnerability", {}).get("fix", {}).get("versions")
            findings.append((repository, severity, not_fixed))
            per_repo_sev.setdefault(repository, Counter())[severity] += 1

    sev_total = Counter(s for _, s, _ in findings)
    not_fixed_total = sum(1 for _, _, nf in findings if nf)

    order = ["Critical", "High", "Medium", "Low"]
    header = (
        f"{'repository':<16}{'total':>6}{'critical':>10}{'high':>7}"
        f"{'medium':>8}{'low':>6}{'not fixed':>11}"
    )
    lines.append(header)

    def repo_line(name, counts, not_fixed):
        return (
            f"{name:<16}{sum(counts.values()):>6}"
            f"{counts.get('Critical', 0):>10}{counts.get('High', 0):>7}"
            f"{counts.get('Medium', 0):>8}{counts.get('Low', 0):>6}{not_fixed:>11}"
        )

    for name in REPOSITORIES:
        counts = per_repo_sev.get(name, Counter())
        nf = sum(1 for r, s, is_nf in findings if r == name and is_nf)
        lines.append(repo_line(name, counts, nf))

    lines.append(
        f"{'TOTAL':<16}{len(findings):>6}"
        f"{sev_total.get('Critical', 0):>10}{sev_total.get('High', 0):>7}"
        f"{sev_total.get('Medium', 0):>8}{sev_total.get('Low', 0):>6}{not_fixed_total:>11}"
    )
    lines.append("")

    pairs = set()
    with (RESULTS_DIR / "vulnerabilities.csv").open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            pairs.add((row["repository"], row["package"]))

    lines.append(f"Total findings: {len(findings)}")
    lines.append(f"Distinct vulnerable (repository, package) pairs: {len(pairs)}")
    if pairs:
        lines.append(f"Findings per vulnerable pair: {len(findings) / len(pairs):.2f}")
    lines.append("")

    lines.append("===== Reachability Sample Outcome =====")
    with (RESULTS_DIR / "final_analysis.csv").open("r", encoding="utf-8") as f:
        sample = list(csv.DictReader(f))

    reach = Counter(row["reachability"] for row in sample)
    for label in ["reachable", "conditionally_reachable", "not_reachable", "unknown"]:
        lines.append(f"{label}: {reach.get(label, 0)}")

    dep = Counter(row["dependency_type"] for row in sample)
    depth = Counter(row["dependency_depth"] for row in sample)
    lines.append("")
    lines.append("By dependency type: " + ", ".join(f"{k}={v}" for k, v in sorted(dep.items())))
    lines.append("By dependency depth: " + ", ".join(f"depth {k}={v}" for k, v in sorted(depth.items())))

    stats_path = RESULTS_DIR / "baseline_stats.txt"
    stats_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {stats_path}")


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    write_sbom_summary()
    write_baseline_stats()


if __name__ == "__main__":
    main()
