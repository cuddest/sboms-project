# SBOM Reachability Study

**From CVEs to reachability: what a package-level vulnerability finding does, and does not, tell you about application risk.**

This repository is the complete artifact set of an empirical study on SBOM-based
Software Composition Analysis (SCA) and the gap between *component presence* and
*vulnerability reachability*.

Eight open-source repositories were qualified through lockfile-consistency checks and
frozen at exact commits. CycloneDX SBOMs were generated with Syft and scanned with
Grype to establish a package-level baseline. A stratified sample of 20 findings was
then traced by hand through advisory metadata, dependency graphs, and application
source code to determine whether the vulnerable functionality is actually reachable.

The study is inspired by Zhou, Dacier, and Konstantinou,
[A Reality Check on SBOM-based Vulnerability Management](https://arxiv.org/abs/2511.20313)
(CODASPY 2026), at deliberately smaller scale with fully manual, evidence-based analysis.

## Key results

| Metric | Value |
| --- | ---: |
| Qualified repositories | 8 |
| Components inventoried (CycloneDX) | 2,315 |
| Package-level vulnerability findings | 246 |
| Distinct vulnerable (repository, package) pairs | 76 |
| Findings manually assessed | 20 |
| Not reachable | **19** |
| Conditionally reachable | **1** |
| Fully reachable | **0** |

> Within this corpus and this stratified sample, 19 of 20 manually assessed findings
> had no identified path to the vulnerable functionality. This is a sample result.
> It is not a false-positive rate for Python software.

The full narrative lives in [`docs/research-article.md`](docs/research-article.md) and on this
[nice blog i made about this project](https://cuddest.github.io/cuddest/writeups/sbom-reachability.html).

## Research questions

- **RQ1.** How many vulnerabilities are reported by package-level scanning?
- **RQ2.** Among sampled findings, how many appear reachable, apparently unreachable, or unclear?
- **RQ3.** Is vulnerability reachability associated with dependency depth?

## Methodology

```
open-source repositories
        |
repository qualification (uv.lock / poetry.lock consistency, no repair)
        |
freeze state (branch + commit, results/repository_manifest.csv)
        |
Syft  ->  CycloneDX JSON SBOM          scripts/generate_sboms.sh
        |
Grype  ->  vulnerability reports       scripts/scan_sboms.sh
        |
normalization                          scripts/normalize_vulnerabilities.py
        |
stratified sample: 2 Critical / 3 High / 10 Medium / 5 Low, seed 42
        |
manual advisory + source investigation (rg, lockfiles, dependency trees)
        |
classification: not_reachable | conditionally_reachable | reachable | unknown
```

Candidate repositories whose committed manifests and lockfiles disagreed were excluded
rather than repaired. Regenerating a lockfile would have replaced the dependency state
the authors actually committed, defeating the purpose of analyzing real published
repository states.

Environment freeze (`results/environment.txt`): Syft v1.51.0, Grype v0.117.0, Python
3.13.11, Git 2.50.1, Grype DB v6.1.9 built 2026-08-22. Scanner output depends on the
advisory database snapshot as much as on tool versions.

## Corpus

| Repository | Focus | Frozen commit |
| --- | --- | --- |
| CantusDB | Django web application | `ae827fc` |
| CoPeP | continual protein learning | `7cceddc` |
| cycode-cli | security CLI tool | `0d44b69` |
| openhands | AI agent platform | `9e8ba84` |
| openpiv-python | scientific Python library | `7e46ce8` |
| pypi-browser | package index browser | `473dfd7` |
| seed | building-energy web platform | `837d3dd` |
| validator | release validation tooling | `b93a7c8` |

Full provenance (upstream URL, branch, commit, date): `results/repository_manifest.csv`.

## Results

### RQ1. Package-level baseline

| Repository | Total | Critical | High | Medium | Low | Not fixed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CantusDB | 0 | 0 | 0 | 0 | 0 | 0 |
| CoPeP | 85 | 0 | 45 | 27 | 13 | 1 |
| cycode-cli | 13 | 0 | 8 | 5 | 0 | 0 |
| openhands | 2 | 0 | 1 | 1 | 0 | 0 |
| openpiv-python | 1 | 0 | 0 | 1 | 0 | 0 |
| pypi-browser | 24 | 1 | 7 | 12 | 4 | 0 |
| seed | 91 | 3 | 53 | 28 | 7 | 17 |
| validator | 30 | 0 | 14 | 11 | 5 | 0 |
| **Total** | **246** | **4** | **128** | **85** | **29** | **18** |

246 findings collapse onto only 76 distinct vulnerable (repository, package) pairs,
about 3.24 findings per pair.

### RQ2. Reachability outcome

| Classification | Findings |
| --- | ---: |
| not_reachable | 19 |
| conditionally_reachable | 1 |
| reachable | 0 |
| unknown | 0 |

Per-finding reasoning: [`results/reachability_analysis.md`](results/reachability_analysis.md).
Classifications are conservative: *not reachable* means no reachable path was
identified in the analyzed source and configuration, never that execution is impossible.

### RQ3. Exploratory breakdowns

| Dependency type | Not reachable | Conditionally reachable |
| --- | ---: | ---: |
| direct | 7 | 1 |
| transitive | 11 | 0 |
| direct dev/test | 1 | 0 |

Depth distribution: depth 1 has 9 findings (8 not reachable, 1 conditional), depth 2
has 6, depth 3 has 4, depth 4 has 1. All depth-2-and-deeper findings were classified as
not reachable. The sample is too small for any causal claim.

### Why findings fail to become vulnerabilities

```
package flagged
      |
      +-- transitive and never referenced         decompress, got, aiohttp, tornado
      +-- development/test tooling only           shell-quote, virtualenv, pytest, setuptools
      +-- package used, vulnerable API unused     requests, hydra-core, torch, angular, starlette
      +-- exploit preconditions absent            jinja2 sandbox scenario
      +-- conditionally reachable                 pygments (F018)
```

The dominant pattern is not "unused package". It is "used package, unused vulnerable
functionality", which is precisely the information a version matcher cannot see.

## Artifacts

```
sboms/                              CycloneDX SBOMs (one per repository)
scans/                              raw Grype JSON reports
results/
    sbom_summary.csv                component counts per SBOM
    vulnerabilities.csv             normalized findings (246 rows)
    reachability_sample.csv         stratified 20-finding sample
    final_analysis.csv              classifications + evidence per finding
    reachability_analysis.md        full per-finding investigation evidence
    repository_manifest.csv         frozen upstream URLs, branches, commits
    baseline_stats.txt              regenerated statistics
    environment.txt                 frozen tool + database versions
scripts/
    generate_sboms.sh               Syft pass over repos/
    scan_sboms.sh                   Grype pass over sboms/
    validate_sboms.sh               non-empty + valid JSON check
    normalize_vulnerabilities.py    scans/*.json -> vulnerabilities.csv
    generate_results.py             recompute summaries and stats
    phase20_visualizations.py       reachability figures
docs/
    research-article.md             full study writeup
```

## Reproduction

Requirements: Syft, Grype, jq, Python 3.13+, uv and Poetry for lockfile validation.

```bash
# clone the eight repositories at the commits in results/repository_manifest.csv
# into repos/<name>, then:
./scripts/generate_sboms.sh repos sboms
./scripts/scan_sboms.sh
./scripts/validate_sboms.sh
python3 scripts/normalize_vulnerabilities.py
python3 scripts/generate_results.py
python3 scripts/phase20_visualizations.py
```

Manual reachability judgments are intentionally not automated; the evidence behind
each one is preserved in `results/reachability_analysis.md` so every classification can
be audited independently.

## Related work

- Li Zhou, Marc Dacier, Charalambos Konstantinou. *A Reality Check on SBOM-based
  Vulnerability Management: An Empirical Study and A Path Forward.* CODASPY 2026,
  pp. 255-268. [DOI](https://doi.org/10.1145/3800506.3803490),
  [arXiv:2511.20313](https://arxiv.org/abs/2511.20313)
- Yunze Zhao et al. *CovSBOM: Enhancing Software Bill of Materials with Integrated Code
  Coverage Analysis.* IEEE ISSRE 2024, pp. 228-237.
  [DOI](https://doi.org/10.1109/ISSRE62328.2024.00031)
- [CycloneDX VEX capabilities](https://cyclonedx.org/capabilities/vex/) and
  [CISA VEX resources](https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary)


## License

MIT for the study code and derived artifacts. The SBOM and scan files describe
third-party open-source projects and remain the property of those projects.
