# Reachability Analysis Evidence (F001 to F020)

This document preserves the reasoning behind every reachability classification in
`results/final_analysis.csv`. The CSV records what was concluded. This file records why.

## Method

Each sampled finding was investigated with the same chain:

```
advisory
  -> affected package and installed version
  -> vulnerable function, module, or trigger condition
  -> application reference search
  -> execution path analysis
  -> attacker-controlled input analysis
  -> classification
```

Classification values are deliberately conservative:

- `not_reachable`: no reachable path to the vulnerable functionality was identified
  in the analyzed source and configuration. This does not mean execution is impossible.
- `conditionally_reachable`: the application reaches code connected to the advisory,
  but the complete exploitation conditions were not established.
- `reachable`: the vulnerable functionality is reached under conditions the application
  exposes. No finding received this classification.
- `unknown`: evidence was insufficient. No finding required this classification.

Searches combined advisory reading, lockfile inspection, dependency-tree inspection,
`rg` source search, and manual code reading of the frozen repository snapshots listed
in `results/repository_manifest.csv`.

## Summary table

| ID | Repository | Package | Version | Advisory | Severity | Dep type | Depth | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F001 | seed | decompress | 4.2.1 | GHSA-mp2f-45pm-3cg9 | Critical | transitive | 3 | not_reachable |
| F002 | seed | shell-quote | 1.8.3 | GHSA-w7jw-789q-3m8p | Critical | transitive | 2 | not_reachable |
| F003 | CoPeP | hydra-core | 1.3.2 | GHSA-2cp2-2r3c-7p7r | High | direct | 1 | not_reachable |
| F004 | seed | shell-quote | 1.8.3 | GHSA-395f-4hp3-45gv | High | transitive | 2 | not_reachable |
| F005 | seed | sqlparse | 0.5.5 | GHSA-prg7-hcfm-mfcr | High | transitive | 2 | not_reachable |
| F006 | CoPeP | tornado | 6.5.4 | GHSA-78cv-mqj4-43f7 | Medium | transitive | 2 | not_reachable |
| F007 | cycode-cli | requests | 2.32.5 | GHSA-gc5v-m9x4-r6x2 | Medium | direct | 1 | not_reachable |
| F008 | pypi-browser | idna | 3.7 | GHSA-65pc-fj4g-8rjx | Medium | transitive | 2 | not_reachable |
| F009 | pypi-browser | jinja2 | 3.1.4 | GHSA-q2x7-8rv6-6q7h | Medium | direct | 1 | not_reachable |
| F010 | pypi-browser | setuptools | 69.5.1 | GHSA-h35f-9h28-mq5c | Medium | transitive | 3 | not_reachable |
| F011 | pypi-browser | virtualenv | 20.26.2 | GHSA-597g-3phw-6986 | Medium | transitive | 2 | not_reachable |
| F012 | seed | angular | 1.8.3 | GHSA-qwqh-hm9m-p5hr | Medium | direct | 1 | not_reachable |
| F013 | seed | got | 7.1.0 | GHSA-pfrx-2q88-qq97 | Medium | transitive | 3 | not_reachable |
| F014 | validator | cryptography | 45.0.7 | GHSA-m2h6-j472-rp4c | Medium | transitive | 4 | not_reachable |
| F015 | validator | pytest | 8.3.5;8.4.2 | GHSA-6w46-j5rx-g56g | Medium | direct-dev-test | 1 | not_reachable |
| F016 | CoPeP | aiohttp | 3.13.3 | GHSA-9x8q-7h8h-wcw9 | Low | transitive | 3 | not_reachable |
| F017 | CoPeP | torch | 2.10.0 | GHSA-rrmf-rvhw-rf47 | Low | direct | 1 | not_reachable |
| F018 | pypi-browser | pygments | 2.18.0 | GHSA-5239-wwwm-4pmq | Low | direct | 1 | conditionally_reachable |
| F019 | pypi-browser | starlette | 0.37.2 | GHSA-jp82-jpqv-5vv3 | Low | direct | 1 | not_reachable |
| F020 | seed | angular | 1.8.3 | GHSA-mqm9-c95h-x2p6 | Low | direct | 1 | not_reachable |

## F001, seed / decompress 4.2.1 (GHSA-mp2f-45pm-3cg9, Critical)

The package enters only through a vendor tooling chain:

```
vendors/package.json declares napa ^3.0.0
napa@3.0.0 -> download@6.2.5 -> decompress@4.2.1
```

`pnpm --dir vendors list napa download decompress --depth 10` confirmed the chain.
No application source references `napa`, `download`, or `decompress`, and no archive
extraction path was identified outside the unused vendor tooling. Dockerfiles copy the
vendor manifests and run `pnpm install`, but no build or runtime step invokes these
packages.

**Classification: not_reachable.** Transitive vendor dependency, no application path.

## F002, seed / shell-quote 1.8.3 (GHSA-w7jw-789q-3m8p, Critical)

The advisory concerns `shell-quote.quote()` with a crafted object token.

Dependency evidence: `npm-run-all@4.1.5 -> shell-quote@1.8.3`. Source search found no
`require("shell-quote")` and no `from "shell-quote"` anywhere in application code.
`npm-run-all` appears only as development tooling behind the lint scripts
(`run-p -c eslint prettier stylelint`).

**Classification: not_reachable.** Development-only dependency; the vulnerable `quote()`
path was not found.

## F003, CoPeP / hydra-core 1.3.2 (GHSA-2cp2-2r3c-7p7r, High)

Hydra is genuinely used. `hydra-core>=1.3.2` is a direct declaration, and
`@hydra.main(...)` appears in `continual_protein/evaluate/run_evaluation.py` and
`scripts/python/pretrain.py`.

The advisory concerns dynamic object instantiation (`hydra.utils.instantiate`,
`_target_`, `_partial_`, `_recursive_`, `_convert_`). None of these were found. The
application uses Hydra as a configuration entry point and reads plain config fields
(`config.model`, `config.tokenizer`, `config.benchmarks`, `config.checkpoint_path`).

**Classification: not_reachable.** Package used, vulnerable instantiate path absent.

## F004, seed / shell-quote 1.8.3 (GHSA-395f-4hp3-45gv, High)

Same package and version as F002 but a different advisory: quadratic-processing DoS in
`shell-quote.parse()`.

Source searches for `shell-quote` imports and `shell-quote.parse(` returned nothing;
generic `parse(` matches were unrelated parsers (`etree.parse`, `dateutil.parser.parse`,
`JSON.parse`). As with F002, shell-quote is only reachable through development tooling.

**Classification: not_reachable.** Same package, different vulnerable API, still unused.

## F005, seed / sqlparse 0.5.5 (GHSA-prg7-hcfm-mfcr, High)

The lockfile pins sqlparse 0.5.5. Searches found no `import sqlparse`, no
`sqlparse.parse()`, `sqlparse.format()`, or `sqlparse.split()` calls anywhere in the
application.

**Classification: not_reachable.** Package present in dependency metadata, no
application usage of the SQL parsing surface identified.

## F006, CoPeP / tornado 6.5.4 (GHSA-78cv-mqj4-43f7, Medium)

The advisory concerns incomplete validation of cookie attributes in
`RequestHandler.set_cookie()`. Tornado enters through `ipykernel -> tornado`. Searches
found no `import tornado`, no `RequestHandler`, and no `set_cookie(` in application
code.

**Classification: not_reachable.** Vulnerable API never referenced by the application.

## F007, cycode-cli / requests 2.32.5 (GHSA-gc5v-m9x4-r6x2, Medium)

Requests is a direct dependency (`requests = ">=2.32.4,<3.0"`) and heavily used:
`requests.post()`, `requests.Session()`, and imports across `cycode/cyclient` and
`cycode/cli`.

The advisory-specific function is `requests.utils.extract_zipped_paths()`. A direct
search returned nothing. The application does handle ZIPs, but through Python's standard
library `zipfile.ZipFile` (for example `cycode/cli/files_collector/models/in_memory_zip.py`)
and uploads them via Requests. That combination does not exercise the vulnerable helper.

**Classification: not_reachable.** Strongest example of "package used, vulnerable API
unused".

## F008, pypi-browser / idna 3.7 (GHSA-65pc-fj4g-8rjx, Medium)

idna 3.7 appears in `poetry.lock` (`idna >=2.8` resolved to 3.7) through the httpx
chain. Searches found no `import idna`, no `idna.encode`, `idna.decode`, or `idna.uts46`
calls in application source.

**Classification: not_reachable.** No application use of the IDNA encoding surface.

## F009, pypi-browser / jinja2 3.1.4 (GHSA-q2x7-8rv6-6q7h, Medium)

Jinja2 is genuinely used:

```python
from starlette.templating import Jinja2Templates
templates = Jinja2Templates(directory=os.path.join(install_root, 'templates'))
```

Routes call `templates.TemplateResponse('package.html', {...})` and similar with fixed
template names. All templates are static files under `pypi_browser/templates/`.
Request-controlled values (package name, filename, archive path, metadata) are passed as
template context variables rendered inside trusted templates, never as template source.

The advisory involves sandbox escape behavior. The application registers three simple
filters (`human_size`, `pluralize`, `anchorize`) that do not execute arbitrary
callables, and no `SandboxedEnvironment` usage was found at all. The exploitation chain
(attacker-controlled template source reaching a sandboxed environment) is therefore not
present in the observed architecture.

**Classification: not_reachable.** Library used, trusted templates only, vulnerable
sandbox condition absent.

## F010, pypi-browser / setuptools 69.5.1 (GHSA-h35f-9h28-mq5c, Medium)

setuptools 69.5.1 is pinned in `poetry.lock` but enters through the tooling chain
`pre-commit -> nodeenv -> setuptools`, not through application requirements.

No `import setuptools`, no sdist generation, no application-level `MANIFEST.in`
processing, and no `FileList` invocation were identified. `pyproject.toml` and
`setup.cfg` exist as packaging metadata, which alone does not put the vulnerable
source-distribution code path into the deployed application's execution. The advisory's
scenario additionally depends on specific filesystem Unicode-normalization conditions.

**Classification: not_reachable.** Packaging tooling present, packaging functionality
never executed by the application.

## F011, pypi-browser / virtualenv 20.26.2 (GHSA-597g-3phw-6986, Medium)

virtualenv enters through `pre-commit -> virtualenv`. It belongs to the development
environment setup, and no production code path invoking it was identified.

**Classification: not_reachable.** Development tooling dependency, no production
invocation.

## F012, seed / angular 1.8.3 (GHSA-qwqh-hm9m-p5hr, Medium)

AngularJS 1.8.3 is present in the seed vendor dependencies and is actually loaded by
the vendor frontend, so this is not an unused-package case. The investigated question
was whether application templates and code exercise the URL-input handling associated
with the advisory. The vulnerable URL-input path was not identified in the analyzed
vendor templates and application code.

**Classification: not_reachable.** Package used, vulnerable URL-input path not
identified.

## F013, seed / got 7.1.0 (GHSA-pfrx-2q88-qq97, Medium)

got arrives through the same vendor chain as F001: `napa -> download -> got`. No
application import of got was found.

**Classification: not_reachable.** Transitive vendor dependency, no application import.

## F014, validator / cryptography 45.0.7 (GHSA-m2h6-j472-rp4c, Medium)

The deepest chain in the sample:

```
twine -> keyring -> secretstorage -> cryptography   (depth 4)
```

No direct application usage of cryptography APIs was identified; the package exists to
satisfy the release-tooling chain.

**Classification: not_reachable.** Depth-4 transitive dependency of release tooling,
no application cryptography usage.

## F015, validator / pytest 8.3.5 and 8.4.2 (GHSA-6w46-j5rx-g56g, Medium)

One advisory matched two simultaneously installed pytest versions, which is itself a
useful observation about how one vulnerability/package pair can correspond to multiple
installed artifacts. Both versions are used only for tests and CI, not by the production
application runtime.

**Classification: not_reachable.** Direct dev/test dependency.

## F016, CoPeP / aiohttp 3.13.3 (GHSA-9x8q-7h8h-wcw9, Low)

aiohttp enters through `datasets -> fsspec[http] -> aiohttp`. No application-level
aiohttp usage was identified; it exists to support optional HTTP access inside the
datasets stack.

**Classification: not_reachable.** Transitive data-tooling dependency, no application
usage.

## F017, CoPeP / torch 2.10.0 (GHSA-rrmf-rvhw-rf47, Low)

Torch is a genuine, central direct dependency of CoPeP and is imported throughout the
training and evaluation code. The advisory concerns the TorchScript surface, and the
investigation did not identify any application use of the vulnerable TorchScript path:
the project trains and runs models directly rather than scripting them.

**Classification: not_reachable.** Core library used, vulnerable subsystem not
identified in use.

## F018, pypi-browser / pygments 2.18.0 (GHSA-5239-wwwm-4pmq, Low)

The one finding that could not be dismissed. pypi-browser genuinely calls Pygments lexer
selection on request-derived input:

```
request path value
  -> archive_path
  -> guess_lexer_for_filename()
  -> Pygments lexers, including AdlLexer
```

So execution really reaches the library's lexer-selection machinery, and request data
influences the choice. What could not be established is the complete set of advisory
conditions beyond that point. Consistent with the conservative scheme, promotion to
fully reachable would have required evidence the analysis did not produce.

**Classification: conditionally_reachable.** Execution reaches the relevant machinery
with influenced input; full trigger conditions unproven.

## F019, pypi-browser / starlette 0.37.2 (GHSA-jp82-jpqv-5vv3, Low)

Starlette is the application's web framework and is obviously exercised. The
investigation targeted the URL/host handling associated with the advisory: no
`request.url` hostname/netloc usage matching the vulnerable pattern was identified in
the application routes.

**Classification: not_reachable.** Framework used, vulnerable pattern not identified.

## F020, seed / angular 1.8.3 (GHSA-mqm9-c95h-x2p6, Low)

Same package and version as F012, different advisory. Searches covered `srcset`,
`ng-srcset`, and `source`/`srcset` template patterns associated with the advisory, and
none were identified in the analyzed templates.

**Classification: not_reachable.** Same package as F012, second vulnerable surface also
not identified.

## Observations recorded across the sample

- One package can appear against multiple advisories with different vulnerable
  functions (shell-quote F002/F004, angular F012/F020), and both surfaces must be
  checked independently.
- One advisory can match multiple installed versions of the same package
  (pytest 8.3.5 and 8.4.2 in F015).
- The most common noise pattern was "package used, vulnerable functionality unused"
  rather than "package entirely unused": hydra-core, requests, jinja2, torch, angular,
  and starlette are all genuinely exercised by their applications.
