# From CVEs to Reachability: Investigating Vulnerability Noise in SBOM-Based Scanning

> An independent, small-scale empirical study inspired by recent research on SBOM accuracy, software supply-chain security, and vulnerability reachability.

2026-08-24

## Abstract

Software Bill of Materials (SBOM) technology is becoming an important part of software supply-chain security. An SBOM can tell us which third-party components are present in a software project, and Software Composition Analysis (SCA) tools can match those components against known vulnerability databases.

The problem is that component presence is not the same thing as application risk.

A vulnerable library can be present through a transitive dependency, a development tool, or a feature that the application never uses. Even when the application actively uses the library, the vulnerable function itself may never be called, or the conditions required to trigger the vulnerability may be absent.

This study investigates that gap.

I built a small, reproducible experiment inspired by the 2025 study *A Reality Check on SBOM-based Vulnerability Management: An Empirical Study and A Path Forward*. Instead of trying to reproduce its large-scale 2,414-repository experiment, I created a smaller corpus of eight qualified open-source repositories, generated CycloneDX SBOMs with Syft, scanned them with Grype, normalized the findings, and manually investigated a stratified sample of 20 vulnerabilities at source level.

The conventional scan produced **246 package-level vulnerability findings**. In the manually assessed sample, **19 of 20 findings (95%) were classified as not reachable**, while **one finding (5%) was conditionally reachable** and none was confirmed as fully reachable.

The result should not be interpreted as a 95% false-positive rate for Python software. The corpus is small and was not sampled randomly. What the experiment does demonstrate is more specific and, in my opinion, more useful: **a package-level vulnerability finding is not enough to establish that the vulnerable functionality is reachable by the application**.

That observation led me to a broader question: how can SBOM and SCA workflows preserve the useful visibility of package-level scanning while adding enough application context to make vulnerability reports more actionable?

---

## 1. Why I Started This Study

I initially approached SBOMs from the normal Software Composition Analysis workflow:

```
source repository
    ↓
SBOM
    ↓
vulnerability scanner
    ↓
CVE findings
    ↓
remediation
```

At first glance, this looks straightforward.

The scanner finds a vulnerable dependency, the developer upgrades it, and the problem is solved.

The more I looked at the workflow, the more I realized that there are actually two different questions hiding inside it:

```
Question 1

Is a vulnerable component present?


Question 2

Does the application actually reach the vulnerable functionality?
```

Those questions are related, but they are not equivalent.

A package can exist in the dependency graph without being imported. It can be imported without the vulnerable function being used. A vulnerable function can be used without attacker-controlled input reaching the relevant trigger condition.

That distinction became the central idea of this project.

---

## 2. The Research I Started From

This study is inspired primarily by Li Zhou, Marc Dacier, and Charalambos Konstantinou's work:

> **A Reality Check on SBOM-based Vulnerability Management: An Empirical Study and A Path Forward**

The study uses 2,414 open-source repositories and examines two weaknesses in the SBOM-based vulnerability-management pipeline.

The first is **SBOM generation itself**. The authors show that using lock files with strong package managers provides a much more reliable dependency representation than relying only on project manifest files.

The second is what happens after an accurate SBOM exists. Their large-scale analysis found a very high false-positive rate in downstream vulnerability reporting and identified unreachable vulnerable code as a primary reason. They then use function-call analysis to reduce a substantial part of that noise.

Their proposed workflow is essentially:

```
accurate SBOM
    ↓
vulnerability scanning
    ↓
reachability / function-call analysis
    ↓
more actionable vulnerability results
```

My experiment follows the same general idea, but at a much smaller scale.

I did not try to reproduce their 2,414 repositories or their full automated reachability pipeline. Instead, I used a smaller independent corpus and performed evidence-based manual reachability analysis.

That distinction is important. This is a **small-scale empirical reproduction and extension**, not a claim to have recreated their complete study.

A useful detail from the original paper is that its evaluation was split into four explicit questions:

1. Can a lock file be generated for projects that initially contain only a project file?
2. Starting from the same lock file, do different SBOM generators produce consistent dependency results?
3. Can SBOM generators produce accurate dependency inventories when the lock file is used as input?
4. Starting from an accurate SBOM, can vulnerability scanners produce accurate vulnerability reports?

The authors use a lock-file-derived dependency set as ground truth for SBOM accuracy, then manually verify vulnerability reports against source code. Their reported results show perfect Jaccard similarity between Syft and Trivy when both start from lock files in the evaluated corpus, and their later vulnerability analysis identifies unreachable code as a major source of false alarms.

My experiment deliberately narrows this scope. I do not reproduce the paper's SBOM-generator comparison or its large-scale lock-file-generation study. I take the accurate-SBOM assumption as the starting point and focus on the second problem: what happens when a package-level scanner reports a vulnerability that may not be reachable by the application.

The original paper is by **Li Zhou, Marc Dacier, and Charalambos Konstantinou**, not Yu et al. It appeared as a 2025 preprint (arXiv:2511.20313) and was published at **CODASPY 2026**, the Sixteenth ACM Conference on Data and Application Security and Privacy.

---

## 3. A Short SBOM and Software Supply-Chain Primer

Before going into the experiment, it helps to define the concepts involved.

### 3.1 Software Supply Chain

The **software supply chain** is the collection of external software, dependencies, build systems, package registries, development tools, and processes that contribute to a software product.

A modern application is rarely built entirely from code written by its own developers.

For example:

```
My application
    ↓
Django
    ↓
requests
    ↓
urllib3
    ↓
some lower-level dependency
```

The deeper the dependency graph becomes, the harder it becomes to manually know exactly what is present and why.

That is where the SBOM idea becomes useful.

### 3.2 Software Bill of Materials

An **SBOM** is a structured inventory of the software components that make up a product.

A useful SBOM can contain information such as:

- package names
- versions
- package identifiers
- relationships between components
- licenses
- suppliers and metadata
- dependency relationships

The important part for this study is that an SBOM describes **what components are present**.

It does not automatically prove:

```
which functions are executed
which vulnerable functions are called
whether an attacker can control the input
whether the vulnerability is exploitable in the deployed context
```

That distinction is the reason an accurate SBOM is necessary, but not sufficient, for accurate vulnerability prioritization.

### 3.3 Project Manifest Files

Most package managers use a **project manifest file** to describe the dependencies a project requests.

Examples include:

| Ecosystem | Package manager | Manifest | Lock file |
| --- | --- | --- | --- |
| Python | Poetry | `pyproject.toml` | `poetry.lock` |
| Python | uv / pip tooling | `pyproject.toml` | `uv.lock` |
| Python | pip | `requirements.txt` / project metadata | traditionally no universal lock format |
| Go | Go Modules | `go.mod` | `go.sum` |
| Rust | Cargo | `Cargo.toml` | `Cargo.lock` |
| JavaScript | npm | `package.json` | `package-lock.json` |
| JavaScript | Yarn | `package.json` | `yarn.lock` |
| Ruby | Bundler | `Gemfile` | `Gemfile.lock` |
| PHP | Composer | `composer.json` | `composer.lock` |

A manifest usually expresses what the project **wants**.

For example:

```
requests = ">=2.32,<3"
```

That is a constraint, not necessarily one exact resolved dependency tree.

### 3.4 Lock Files

A lock file records a resolved dependency state.

Conceptually:

```
Manifest

requests >=2.32
```

becomes something closer to:

```
Lock file

requests 2.32.5
urllib3 2.5.0
charset-normalizer ...
certifi ...
idna ...
```

This distinction matters because SBOM generation needs an accurate picture of the dependencies that are actually resolved.

The study that motivated this project found that strong package managers and lock files produced much more consistent SBOM results than weaker manifest-only workflows.

### 3.5 Strong and Weak Package Managers

The paper distinguishes package managers based on how completely they resolve dependencies.

A **strong package manager** explicitly resolves the dependency graph, including transitive dependencies, and can produce a lock file that records the resolved state.

A **weak package manager** may rely more heavily on incomplete or unconstrained dependency declarations and provide less deterministic dependency resolution.

Examples from the paper include:

```
Python
    Poetry        strong
    pip           weak

Go
    Go Modules    strong

Rust
    Cargo         strong

Java
    Gradle        strong

JavaScript
    npm           strong
    Yarn          strong

Ruby
    Bundler       strong

PHP
    Composer      strong
```

This does not mean that a "weak" package manager is unusable. The point is that SBOM generation becomes more difficult when the input does not contain a precise, reproducible dependency resolution.

---

## 4. Why Accurate SBOM Generation Is the First Problem

The paper frames the overall situation as two separate problems.

### Problem 1: generating an accurate SBOM

If the SBOM is incomplete or inconsistent, every downstream security analysis starts from the wrong dependency inventory.

For example:

```
real dependency graph
       ↓
incomplete SBOM
       ↓
missing package
       ↓
missing vulnerability
```

or:

```
real dependency graph
       ↓
incorrect SBOM
       ↓
wrong version
       ↓
incorrect vulnerability result
```

This is why the lock file matters.

The authors experimentally compared SBOM generation from lock files and manifest-only inputs. With lock files, Syft and Trivy produced consistent results across the ecosystems in their dataset. They reported a Jaccard similarity of 1.0 for the lock-file-based SBOM comparison.

The first research lesson is therefore:

> **Garbage in at the dependency layer produces unreliable security analysis downstream.**

---

## 5. The Second Problem: An Accurate SBOM Can Still Produce Noisy Vulnerability Reports

This is the part I was most interested in.

Suppose the SBOM is correct.

The scanner sees:

```
jinja2 3.1.4
```

and its vulnerability database says:

```
Jinja2 3.1.4
affected by GHSA-...
```

The scanner is doing its job.

But now another question appears:

```
Does the application actually reach
the vulnerable Jinja2 functionality?
```

This is the second problem.

A package-level matcher usually answers:

```
affected package + affected version = finding
```

Application-aware analysis asks:

```
affected package
    ↓
affected module
    ↓
affected function
    ↓
application call path
    ↓
attacker-controlled input
    ↓
vulnerability trigger
```

The second chain is much harder to establish.

---

## 6. Where VEX Fits

A related concept is **Vulnerability Exploitability eXchange**, or VEX.

VEX is a machine-readable way of communicating whether a known vulnerability affects a specific product in its actual context. CISA describes VEX as a way to communicate whether a product is affected by a specific vulnerability, and CycloneDX supports VEX as part of its BOM ecosystem.

For example, after analysis a supplier might communicate:

```
Component: jinja2
Vulnerability: GHSA-...
Status: Not Affected
Reason: vulnerable_code_not_in_execute_path
```

That is extremely useful.

But VEX does **not** magically solve the reachability problem.

It solves the **communication problem**:

```
analysis result
      ↓
VEX statement
      ↓
downstream consumers
```

It does not inherently produce:

```
CVE
 ↓
call graph
 ↓
reachable function
```

Someone or something still has to perform the analysis that justifies the VEX status.

This distinction is important for this project:

```
SBOM
    tells us what is present

Reachability analysis
    tells us what appears to be used

VEX
    communicates the exploitability assessment
```

So VEX is not a replacement for the analysis. It is a way to carry the result of that analysis between organizations and tools.

CycloneDX explicitly supports VEX, and CISA maintains VEX guidance and minimum requirements for machine-readable exploitability statements.

---

## 7. CovSBOM and the Same General Problem

Another paper that helped me understand where this research space is going is:

> **CovSBOM: Enhancing Software Bill of Materials with Integrated Code Coverage Analysis**

CovSBOM was presented at ISSRE 2024.

The core idea is very close to the question explored here: an SBOM can tell us what dependencies exist, but it does not necessarily tell us which parts of those dependencies are actually exercised by the application.

CovSBOM integrates code coverage information into the SBOM context to improve the understanding of which third-party code is actually used.

The authors evaluated their approach on 23 large-scale applications, covering 1,614 dependencies and 145 vulnerability alerts. They report that CovSBOM identified 105 false-positive cases and improved vulnerability-detection precision by about 72%.

I did not implement CovSBOM in this project.

I use it as related work because it shows that the gap between:

```
dependency inventory
```

and:

```
actual dependency usage
```

is not limited to one paper or one scanner.

There are multiple research directions trying to enrich software-component inventories with execution or usage information.

---

## 8. My Experimental Question

Instead of attempting to repeat the full scale of the original study, I narrowed the problem to something that I could actually investigate on my own.

The main question became:

> **When an SBOM/SCA scanner reports a vulnerable dependency, how often can I establish a reachable path to the vulnerable functionality in a small, independently selected corpus?**

I also explored a secondary question:

> **Does dependency depth appear to correlate with apparently unreachable findings?**

The second question is exploratory. I do not claim that deeper dependencies cause unreachability.

---

## 9. Experimental Design

The complete experiment was:

```
Open-source repositories
        ↓
Repository qualification
        ↓
Lock-file validation
        ↓
Freeze repository state
        ↓
Syft
        ↓
CycloneDX SBOM
        ↓
Grype
        ↓
Vulnerability baseline
        ↓
Normalize findings
        ↓
Stratified 20-finding sample
        ↓
Manual advisory analysis
        ↓
Source-code investigation
        ↓
Reachability classification
```

The final corpus contained eight repositories:

```
CantusDB
CoPeP
cycode-cli
OpenHands
OpenPIV-python
pypi-browser
SEED
validator
```

The corpus is primarily Python-oriented, although SEED also contains JavaScript dependency material.

---

## 10. Repository Qualification

I did not simply choose eight repositories and scan them.

Before generating an SBOM, I checked whether repositories had usable dependency metadata.

The qualification process looked for:

- a real software project
- Python-centric application or library code
- usable dependency metadata
- a lock file where possible
- meaningful source code
- reproducible dependency resolution
- a stable repository state
- no obvious reason that the dependency graph would be dominated by vendored code

Both `uv.lock` and `poetry.lock` were considered.

I also automated repository discovery so that the experiment was not dependent on a hard-coded list.

This turned out to matter.

Several candidate projects were removed because their current project manifest and lock file were inconsistent.

That is useful experimental evidence in itself. It reinforced the motivation for treating dependency-state reproducibility as a qualification criterion rather than assuming every lock file is automatically trustworthy.

Importantly, I did not repair failing repositories by regenerating their lock files. Running `uv lock` or `poetry lock` would have produced a new dependency state that the original authors never committed, and the study would no longer have been analyzing real published repository states.

---

## 11. Freezing the Repository State

For each accepted repository, I recorded its branch and exact Git commit. All snapshots are listed in `results/repository_manifest.csv`.

That matters because open-source repositories keep changing.

Without a frozen commit:

```
today
    ↓
SBOM

one month later
    ↓
different dependency graph
```

The experiment therefore analyzes a specific snapshot, not an ever-changing project.

The same principle applies to the vulnerability scanner database.

---

## 12. Tooling

The practical workflow used open-source tools:

```
uv
Poetry
Syft
Grype
jq
Python
ripgrep
Git
```

The main pipeline was intentionally simple:

```
Syft
    ↓
CycloneDX JSON
    ↓
Grype
    ↓
JSON vulnerability report
```

The environment was frozen as part of the experiment.

The recorded environment included:

```
Syft: v1.51.0
CycloneDX schema: 16.1.10
Grype: v0.117.0
Python: 3.13.11
Git: 2.50.1
Grype DB schema: v6.1.9
```

The Grype vulnerability database used in the experiment was built on:

```
2026-08-22T06:14:16Z
```

This is important because scanner results depend not only on the scanner version but also on the vulnerability database snapshot.

---

## 13. Generating the SBOMs

Syft generated CycloneDX JSON SBOMs for all eight repositories.

The approximate package counts reported during generation were:

| Repository | Syft package count |
| --- | ---: |
| CantusDB | 94 |
| CoPeP | 141 |
| cycode-cli | 128 |
| OpenHands | 709 |
| OpenPIV-python | 33 |
| pypi-browser | 51 |
| SEED | 1,017 |
| validator | 91 |

The exact component counts stored in the CycloneDX files differ slightly (for example CantusDB has 98 components) because the terminal summary and the SBOM document are not guaranteed to count identical things. Both observations are recorded rather than silently reconciled.

I also learned an operational lesson here.

The generated SBOM files needed more careful validation than simply running:

```
jq empty file.json
```

An empty file can produce misleading behavior with a loose JSON check.

The stronger validation was:

```
[ -s "$file" ] && jq -e . "$file"
```

This checks both that the file exists with non-zero size and that it contains valid JSON.

---

## 14. Package-Level Vulnerability Baseline

Grype produced the initial package-level baseline.

The result was:

| Repository | Total | Critical | High | Medium | Low | Not fixed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CantusDB | 0 | 0 | 0 | 0 | 0 | 0 |
| CoPeP | 85 | 0 | 45 | 27 | 13 | 1 |
| cycode-cli | 13 | 0 | 8 | 5 | 0 | 0 |
| OpenHands | 2 | 0 | 1 | 1 | 0 | 0 |
| OpenPIV-python | 1 | 0 | 0 | 1 | 0 | 0 |
| pypi-browser | 24 | 1 | 7 | 12 | 4 | 0 |
| SEED | 91 | 3 | 53 | 28 | 7 | 17 |
| validator | 30 | 0 | 14 | 11 | 5 | 0 |
| **Total** | **246** | **4** | **128** | **85** | **29** | **18** |

This is the first point where the distinction between scanner output and application risk becomes important.

The correct statement is:

> The conventional SBOM/SCA workflow reported 246 package-level vulnerability findings.

The incorrect statement would be:

> The experiment found 246 exploitable vulnerabilities.

I did not establish that.

---

## 15. Normalizing the Findings

Eight raw Grype JSON outputs are difficult to analyze manually.

I therefore created:

```
results/vulnerabilities.csv
```

with fields including:

```
repository
package
installed_version
vulnerability_id
severity
fixed_version
dependency_type
```

This produced a normalized dataset of 246 findings.

The dataset contained 76 distinct `(repository, package)` pairs associated with vulnerabilities.

That gives:

```
246 / 76 ≈ 3.24
```

or roughly 3.24 findings per vulnerable repository/package pair.

This is not a global measure of unique packages. It is simply a descriptive statistic of this corpus.

---

## 16. Why I Did Not Manually Investigate All 246 Findings

Tracing every finding manually would have made the study much larger without necessarily improving the quality of the research question.

Instead, I created a stratified sample of 20 findings:

```
2 Critical
3 High
10 Medium
5 Low
```

A deterministic random seed of 42 was used.

The sample therefore deliberately covers different severity levels instead of reflecting the natural distribution of the 246 findings.

This distinction matters.

The sample's 10% Critical, 15% High, 50% Medium, and 25% Low distribution is a property of the **sampling design**, not a statement about the corpus.

---

## 17. The Reachability Method

For every sampled vulnerability, I followed the same general process.

### Step 1

Read the vulnerability advisory.

I needed to know exactly what the vulnerability depends on.

### Step 2

Confirm that the scanned package/version is actually present.

### Step 3

Identify the vulnerable module, function, API, or trigger condition.

### Step 4

Search the application source.

I used tools such as:

```
rg
```

together with dependency metadata and source inspection.

### Step 5

Determine whether the application actually reaches the vulnerable functionality.

### Step 6

Where relevant, ask whether attacker-controlled data can reach the vulnerable operation.

This produced the following conceptual model:

```
Package present
    ↓
Affected version
    ↓
Vulnerable code
    ↓
Application reference
    ↓
Execution path
    ↓
Attacker-controlled input
    ↓
Trigger condition
```

I intentionally used conservative classifications:

```
not_reachable
conditionally_reachable
reachable
unclear
```

---

## 18. What the 20 Findings Actually Showed

The final sample produced:

```
Not reachable           19
Conditionally reachable  1
Confirmed reachable      0
Unclear                  0
```

Therefore:

```
19 / 20 = 95% not reachable
1 / 20 = 5% conditionally reachable
```

I want to be very precise here.

This does **not** mean:

> "95% of Python vulnerabilities are false positives."

It means:

> **Within this eight-repository corpus and this 20-finding stratified sample, 19 findings did not have an identified reachable path to the vulnerable functionality.**

That is the result I can actually defend.

---

## 19. The Most Useful Part of the Investigation

The value of the manual analysis was not only the 95% number.

The findings exposed several different reasons for scanner noise.

### 19.1 Transitive dependency that is never used

Example:

```
napa
 ↓
download
 ↓
decompress
```

The vulnerable package existed in the dependency graph, but no application path to the vulnerable functionality was identified.

### 19.2 Development-only dependency

Examples included:

```
shell-quote
virtualenv
pytest
setuptools
```

These were associated with tooling, tests, linting, or development workflows rather than the production runtime.

A package-level scanner can still see them because they are part of the resolved environment.

### 19.3 Package genuinely used, vulnerable function not used

This was one of the most interesting categories.

Examples included:

```
hydra-core
requests
jinja2
angular
torch
starlette
```

These are not "unused dependencies."

The application really uses them.

The important distinction is:

```
package is used
      ≠
vulnerable functionality is used
```

For example, `requests` is heavily used in cycode-cli, but the vulnerable `extract_zipped_paths()` functionality associated with the advisory was not found in the application code.

That was one of the clearest demonstrations that package-level reachability is not enough.

---

## 20. Example: Jinja2

One of the strongest examples was:

```
pypi-browser
    ↓
Jinja2 3.1.4
```

The application really uses Jinja2:

```
Jinja2Templates(...)
```

and renders templates through `TemplateResponse`.

So it would be wrong to say:

> "The finding is irrelevant because Jinja2 is not used."

It is used.

The actual analysis asked a more specific question:

```
Does attacker-controlled input become Jinja template source
and reach the vulnerable sandbox behavior?
```

The application uses static, trusted templates and passes request/package information as template context.

No use of `SandboxedEnvironment` was identified.

Therefore:

```
Jinja2 used
    ↓
trusted template source
    ↓
vulnerable sandbox condition absent
    ↓
not reachable
```

This was one of the clearest examples of why a vulnerability's affected **functionality** matters more than simply the library name.

---

## 21. Example: Setuptools

Another useful case was `setuptools`.

The vulnerable version was present:

```
setuptools 69.5.1
```

but the dependency chain was:

```
pre-commit
    ↓
nodeenv
    ↓
setuptools
```

No application import of setuptools was identified.

The repository contained packaging metadata, but that did not prove that the production application executed the vulnerable source-distribution functionality.

The important distinction was:

```
package exists
    ≠
application executes package
```

---

## 22. Example: Hydra

Hydra showed an even more subtle case.

CoPeP actually uses:

```
hydra-core
```

and invokes:

```
@hydra.main(...)
```

But the vulnerable functionality associated with dynamic object instantiation was not identified.

So:

```
Hydra used
    ↓
vulnerable feature not identified
    ↓
not reachable
```

This type of finding is exactly why a binary "package vulnerable / package safe" decision can be misleading.

---

## 23. The One Conditionally Reachable Case

The only finding that did not fall into `not_reachable` was:

```
F018
pypi-browser
pygments 2.18.0
```

The application genuinely calls:

```
guess_lexer_for_filename()
```

with an `archive_path`.

The path looked like:

```
pypi-browser
    ↓
archive_path
    ↓
guess_lexer_for_filename()
    ↓
Pygments
    ↓
AdlLexer
```

This demonstrated that execution really can reach Pygments lexer selection and that the archive path influences the lexer choice.

However, that still did not establish the complete advisory exploitation conditions.

Therefore I deliberately classified it as:

```
conditionally_reachable
```

rather than:

```
reachable
```

This is a useful distinction.

Reachability is not the same as proving exploitability.

---

## 24. Dependency Depth

I also recorded dependency depth as an exploratory variable.

The sample contained:

```
Depth 1 → 9
Depth 2 → 6
Depth 3 → 4
Depth 4 → 1
```

The distribution was:

```
Depth 1
    8 not reachable
    1 conditionally reachable

Depth 2
    6 not reachable

Depth 3
    4 not reachable

Depth 4
    1 not reachable
```

Every sampled depth-2, depth-3, and depth-4 finding was classified as not reachable.

This is interesting, but I am deliberately **not** claiming:

> greater dependency depth causes unreachability.

The sample is too small, and depth is correlated with other variables such as transitive dependencies and development tooling.

The responsible conclusion is:

> In this exploratory sample, deeper dependency findings were all classified as not reachable, but the experiment is too small to establish a causal relationship.

---

## 25. What the Scanner Saw Versus What the Application Used

This is the simplest way to summarize the whole experiment.

The scanner sees:

```
Component
   +
Version
   +
Vulnerability advisory
```

My manual analysis adds:

```
Component
   ↓
Version
   ↓
Vulnerable functionality
   ↓
Application usage
   ↓
Execution path
   ↓
Trigger conditions
```

That extra context changes the interpretation of a finding.

---

## 26. Why VEX Still Matters

At this point VEX becomes useful again.

Suppose the analysis establishes:

```
vulnerable code not reached
```

That information is valuable to the application's users, customers, auditors, and downstream security teams.

VEX provides a standardized way to communicate it.

So the complete ecosystem looks more like:

```
SBOM
  ↓
What components exist?

SCA
  ↓
Which components match known vulnerabilities?

Reachability analysis
  ↓
Which vulnerable functionality appears to matter?

VEX
  ↓
How do we communicate the assessment?
```

The first three stages create or refine the evidence.

VEX communicates the conclusion.

That is why I would not describe VEX as a replacement for reachability analysis.

---

## 27. What This Project Demonstrates

The strongest result of the project is not:

> "SCA tools produce false positives."

That is too broad.

The stronger conclusion is:

> **Package-level SCA establishes that an affected component version exists in the analyzed dependency graph, but this alone does not establish that the vulnerable functionality is reachable by the application.**

The manual investigation exposed several distinct gaps between package presence and application impact:

```
transitive dependencies
development dependencies
unused library functionality
unused vulnerable APIs
missing exploitation conditions
missing attacker-controlled input paths
```

This is why context matters.

---

## 28. What the Original Study Adds to This Picture

The paper I started from investigated this at a much larger scale.

Its contribution can be understood as two connected observations:

```
Problem 1
Accurate SBOM generation

Problem 2
Accurate vulnerability interpretation
```

The first problem is addressed by using strong package managers and lock files as reliable dependency inputs.

The second problem requires application-level information such as function-call or reachability analysis.

The paper reports that, in its large-scale study, lock files produced consistent SBOMs and that downstream vulnerability analysis still suffered from substantial noise. It then showed that function-call analysis could reduce a significant part of that noise.

My study asks a smaller, more hands-on question:

> Does the same qualitative gap become visible when I independently follow a small set of real open-source projects from lockfile validation all the way to source-level vulnerability investigation?

Within the limits of the experiment, the answer is yes.

---

## 29. Limitations

This is the section I care about most because it prevents the results from being overstated.

### Small corpus

Only eight repositories were analyzed.

Only twenty vulnerability findings were manually assessed.

Therefore:

```
95% not reachable
```

cannot be generalized to Python software as a whole.

### Non-random repository selection

The repositories were selected using practical qualification criteria.

They were not randomly sampled from all Python software.

The corpus therefore represents a research sample, not the Python ecosystem.

### Single main ecosystem

The study is primarily Python-focused, although SEED contains JavaScript dependency material.

The results do not establish that the same behavior occurs in Java, Go, Rust, .NET, Ruby, C++, or other ecosystems.

### Manual analysis

The reachability classification depended on source inspection and analyst judgment.

A second analyst could classify an ambiguous path differently.

For that reason, I use:

> **evidence-based reachability classification**

rather than claiming formal proof of non-executability.

### Static-analysis limitations

Much of the investigation used:

```
ripgrep
dependency inspection
lockfile inspection
source search
configuration inspection
```

This can miss:

- dynamic imports
- reflection
- generated code
- plugin loading
- runtime dispatch
- environment-specific code paths

Therefore:

> **not reachable** means that no reachable path was identified in the analyzed source and configuration.

It does not mean that it is mathematically impossible for the code to execute.

### Dynamic behavior

The study did not execute every application across all possible:

- configuration states
- feature flags
- environment variables
- plugins
- deployment modes

Some runtime-dependent paths could therefore remain undiscovered.

### Scanner and database dependence

The 246-finding baseline depends on:

```
Syft version
Grype version
Grype vulnerability database
advisory metadata
```

A different database snapshot can produce different findings.

That is why the experiment records the tool and database versions.

### Dependency depth

Dependency depth describes the dependency graph.

It does not describe runtime call depth.

A package at dependency depth 3 is not automatically three calls away from the vulnerable function.

---

## 30. Reproducibility

One of the things I wanted from this project was for the experiment to be more than a collection of terminal commands.

The final workflow has a reproducibility chain:

```
repository snapshot
       ↓
lockfile validation
       ↓
SBOM
       ↓
Grype scan
       ↓
normalized dataset
       ↓
20-finding sample
       ↓
manual evidence
       ↓
final analysis
       ↓
metrics
       ↓
environment/tool versions
```

The repository stores the artifacts needed to inspect that chain, including per-finding evidence in `results/reachability_analysis.md` and frozen repository snapshots in `results/repository_manifest.csv`.

The environment was frozen on:

```
2026-08-24
```

with the recorded Syft, Grype, Python, Git, and vulnerability database versions.

---

## 31. Repository Structure

The research repository contains artifacts such as:

```
sboms/
    *.json

scans/
    *.json

results/
    sbom_summary.csv
    vulnerabilities.csv
    reachability_sample.csv
    final_analysis.csv
    reachability_analysis.md
    repository_manifest.csv
    baseline_stats.txt
    environment.txt
    syft-version.txt
    grype-version.txt

scripts/
    generate_sboms.sh
    scan_sboms.sh
    validate_sboms.sh
    normalize_vulnerabilities.py
    generate_results.py
    phase20_visualizations.py
```

The important distinction is that:

```
sboms/
```

contains the machine-readable dependency inventories,

```
scans/
```

contains scanner output,

and:

```
results/
```

contains the normalized and interpreted research data.

---

## 32. What I Would Build Next

The study is deliberately small.

That leaves a clear path for extending it.

The most interesting next step would be to automate the manual second stage.

A future pipeline could be:

```
SBOM
  ↓
SCA
  ↓
vulnerable package
  ↓
advisory metadata
  ↓
vulnerable symbols/functions
  ↓
call graph
  ↓
application entry points
  ↓
reachable vulnerability
```

The biggest challenge is not generating the SBOM.

It is obtaining reliable **vulnerability-to-code metadata**.

That is especially interesting across languages.

For example, Go vulnerability information can provide structured affected symbols, making the connection between an advisory and program analysis much more direct. Other ecosystems do not provide equally complete symbol-level information for every vulnerability.

A future version could therefore investigate:

> **Can advisory-level vulnerable-symbol metadata be automatically combined with language-specific call-graph analysis to produce machine-generated reachability assessments?**

That would move this project from an exploratory study into an actual research/tool-building direction.

---

## 33. Possible Automated Architecture

The next version could look like:

```
                Repository
                    ↓
               Lock file
                    ↓
                  SBOM
                    ↓
              SCA scanner
                    ↓
             Vulnerability
               findings
                    ↓
          Vulnerability metadata
                    ↓
           Vulnerable symbols
                    ↓
             Call-graph engine
                    ↓
         Application entry points
                    ↓
             Reachability
                    ↓
        ┌───────────┼───────────┐
        ↓           ↓           ↓
  Not reachable  Conditional  Reachable
        ↓           ↓           ↓
               VEX / triage
```

That is where the project could continue if I wanted to turn it into a larger PFE or research project.

And it is where I intend to take it.

The manual study settled the question I personally needed answered: the gap between package presence and reachable risk is real, measurable, and varied enough to matter. The next stage is to automate what I did by hand.

Concretely, I want to build the pipeline sketched above, and I plan to start with the piece the entire idea depends on: advisory-to-symbol metadata. Go is the most practical first ecosystem because its vulnerability database already provides structured information about affected symbols and functions. That directly attacks the biggest obstacle in this research space, which is not generating the SBOM but knowing which code inside a vulnerable package actually contains the flaw.

Python would come next, where import graphs and language dynamism make the problem harder, and where coverage-based signals in the spirit of CovSBOM become useful complements rather than replacements.

The long-term target is a tool that consumes an accurate, lock-file-based SBOM, runs standard SCA, and emits machine-generated reachability assessments that stay honest about uncertainty, with VEX as a natural export format for the conclusions.

The experiment in this repository was the small-scale proof that the problem is worth solving. The next version is an attempt to solve it.

---

## 34. Conclusion

This project started from a simple workflow:

```
SBOM → scanner → CVEs
```

The experiment made it clear that this workflow hides an important distinction.

An SBOM can tell us that a vulnerable package is present.

A vulnerability scanner can tell us that the package version matches an advisory.

Neither result alone establishes that the vulnerable functionality is reachable by the application.

Across eight repositories, my conventional package-level SCA baseline produced **246 vulnerability findings**.

From a deliberately stratified sample of 20 findings, I manually investigated the actual dependency paths, affected APIs, application usage, and trigger conditions.

The result was:

```
19 not reachable
1 conditionally reachable
0 confirmed reachable
```

or:

```
95% not reachable
5% conditionally reachable
0% confirmed reachable
```

within the investigated sample.

I do not interpret that as a universal false-positive rate.

The real conclusion is more useful:

> **Package presence is not the same as vulnerable functionality reachability.**

The difference appeared in several forms:

```
transitive dependency
development dependency
unused library functionality
unused vulnerable APIs
missing trigger conditions
missing attacker-controlled paths
```

This is why a more complete software-supply-chain security workflow needs to connect three different ideas:

```
SBOM
    ↓
What is present?

Vulnerability analysis
    ↓
What is known to be vulnerable?

Reachability analysis
    ↓
What actually matters in this application?
```

And when that assessment needs to be communicated downstream:

```
VEX
```

provides the language for expressing the product-level exploitability decision.

For me, the most interesting part of the project was not seeing a scanner produce hundreds of CVEs. It was taking those findings one by one and discovering why the package-level answer was often not the same as the application-level answer.

That gap between static dependency inventories and actual software behavior is where I would continue this work.

---

## References

1. Li Zhou, Marc Dacier, Charalambos Konstantinou. **A Reality Check on SBOM-based Vulnerability Management: An Empirical Study and A Path Forward.** Proceedings of the Sixteenth ACM Conference on Data and Application Security and Privacy (CODASPY 2026), pp. 255-268, ACM, 2026. Preprint: arXiv:2511.20313.
   https://doi.org/10.1145/3800506.3803490
   https://arxiv.org/abs/2511.20313
2. Yunze Zhao, Yuchen Zhang, Dan Chacko, Justin Cappos. **CovSBOM: Enhancing Software Bill of Materials with Integrated Code Coverage Analysis.** IEEE ISSRE 2024, pp. 228-237.
   https://doi.org/10.1109/ISSRE62328.2024.00031
3. OWASP CycloneDX. **CycloneDX Specification and VEX capabilities.**
   https://cyclonedx.org/specification/overview/
   https://cyclonedx.org/capabilities/vex/
4. CISA. **Vulnerability Exploitability eXchange (VEX) Resources.**
   https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary
5. CISA. **VEX Use Cases Document.**
   https://www.cisa.gov/sites/default/files/publications/VEX_Use_Cases_Document_508c.pdf
