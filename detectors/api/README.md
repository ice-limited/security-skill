# detectors/api/

API-specific security review — **three mechanisms**, not one, each
covering a distinct slice of CONTEXT.md §7's API sub-skill scope. See
`plans/012-api-skill.md` and
`meetings/2026-07-22-2200-plan-012-kickoff.md` in the
security-skill-workspace repo for design rationale.

| Module | Mechanism | Covers |
|---|---|---|
| `scanner.py` | Spectral (`@stoplight/spectral-cli` + `@stoplight/spectral-owasp-ruleset`), subprocess | OpenAPI spec-lint: 16 curated OWASP API Security Top 10 (2023) rules readable directly from the spec file |
| `open_redirect.py` | Semgrep (`common/semgrep_wrapper.py`), subprocess | Open redirect (CWE-601) in application code — zero overlap with 007/023 |
| `crossref.py` + `spec_analysis.py` | deterministic spec parsing + playbook guidance | Spec-aware cross-reference: does the code actually enforce what the spec declares as secured? |

## Setup

```
npm install                       # in this directory — installs Spectral + its OWASP ruleset locally
pip install -r requirements.txt   # PyYAML + ruamel.yaml, for spec_analysis.py/scanner.py's discovery heuristic
```

`semgrep` itself is not re-declared here — already required by
`detectors/code-review/requirements.txt` (007), same precedent 023
already follows for not re-declaring it either.

**This is the first tool in the project needing a non-Python runtime**
(Node.js/npm) — decided at the plan 012 kickoff after comparing against
`vacuum` (a Go binary) and a hand-rolled Python alternative; the user
chose Spectral for its ruleset's direct, actively-maintained mapping to
the OWASP API Security Top 10 2023 edition. `scanner.py` invokes it via
`npx spectral ...` with this directory as `cwd`, so the locally
installed CLI/ruleset resolve — a bare `npx --yes @stoplight/spectral-
cli` from an arbitrary directory does **not** resolve the ruleset's
`extends` target (verified for real at implementation), which is why a
local `node_modules` + explicit `--ruleset` path is required, not
optional.

## `scanner.py` — OpenAPI spec-lint (16 curated rules)

`rules.py` curates 26 of the ruleset's 31 total rule codes (API1/2/3/4/
5/7/8:2023) down to 16 `rule_id`s, each hand-mapped to a CWE + OWASP-
API-Top10 reference (the ruleset's own codes carry only an OWASP
category tag, no CWE — same situation 009/010/011 found with Trivy/
Checkov). Excluded as a judgment call (documentation-completeness
checks with no direct attacker-relevant CIA impact, mirroring 011's own
`CKV_AWS_135` precedent): the three `api8:2023-define-error-*` rules and
the two `api9:2023-inventory-*` rules.

Two real Spectral quirks shaped both the rule catalog and its fixtures
(verified directly against the CLI, not assumed):
- `no-additionalProperties`/`constrained-additionalProperties` only
  fire when `additionalProperties` is *explicitly* `true` (or an
  unconstrained sub-schema) — omitting the keyword entirely does not
  trigger either.
- `no-unevaluatedProperties`/`constrained-unevaluatedProperties` only
  fire for `openapi: 3.1.x` documents — the identical node produces
  zero findings under `3.0.3`.

A directory input is searched for files that look like an OpenAPI spec
(`.yaml`/`.yml`/`.json` with a top-level `openapi`/`swagger` key) rather
than assuming every YAML/JSON file in it is one — verified this doesn't
misfire on an unrelated file (e.g. `docker-compose.yml`) sitting
alongside the real spec.

Exit-code contract, verified empirically (a fourth distinct convention
among this project's four wrapped external tools — see `scanner.py`'s
own docstring for the full comparison against Semgrep/Trivy/Checkov):
`0`/`1` both mean "ran, parse the JSON regardless"; `>=2` is a genuine
invocation error. `code: "parser"` pseudo-findings for a malformed input
file are not a special case — they simply don't match any curated code
and are silently skipped.

## `open_redirect.py` — CWE-601, the one class with zero overlap risk

Merges `p/owasp-top-ten` (Express/JS coverage) and `p/security-audit`
(Flask/Python coverage) — no single pack covers both, verified for
real. A genuine cross-config duplicate was found at implementation
(two distinct check_ids firing on the same Express line) and is fixed
via `rule_id_overrides` + de-dup by `(file, startLine, endLine)`, the
same mechanism 023 already uses for its own JWT check_ids.
`test_open_redirect.py`'s `NoOverlapWith023Tests` runs both this module
and 023's `semgrep_detector.py` (as real subprocesses, not in-process
imports — each detector directory manages its own `sys.path`) against
each other's fixtures and asserts zero cross-contamination.

## `crossref.py` + `spec_analysis.py` — spec-aware cross-reference

**Deliberately mirrors detectors/auth's (023) hybrid precedent**,
decided at implementation rather than the kickoff: `spec_analysis.py`
deterministically parses the OpenAPI spec (via `ruamel.yaml`'s
round-trip loader, for real line numbers) and extracts every operation
declared as requiring a security scheme — respecting global-vs-
operation-level `security` inheritance and explicit `security: []`
overrides. `crossref.py` renders that list as playbook guidance for the
invoking agent to correlate against the implementation's actual route
handlers, the same shape 023's own README documents ("this sub-skill
has no deterministic scanner for most of cpmatch's stack ... the agent
reads this checklist and reasons over the code directly") — building a
bespoke per-framework route extractor (Flask/Express/FastAPI/Spring/...)
would either be dishonest about its real coverage across cpmatch's
13+-language stack, or a large multi-framework effort this plan's
kickoff explicitly deferred rather than assumed away.

Kept as a single plain Python constant, not a JSON+schema checklist
infrastructure like 023's `checklist.json`/`checklist.schema.json` —
that shape earns its weight across 023's ~6 items with per-language
notes; duplicating it for exactly one item here would be process
ceremony without a second real consumer (plan 005's "share once a
second consumer exists" precedent, applied to *not* building the
abstraction yet).

Scoped to **spec-aware cross-reference only** — never a
re-implementation of 023's generic JWT-bypass/mass-assignment pattern
detection (the real duplicate-finding risk found and resolved at this
plan's kickoff, see the meeting note). `ruleId`
(`api.spec-declared-auth-missing-in-code`) is namespaced distinctly
from both `api.*` spec-lint rules and 023's `auth.*` rules.

## Usage

```python
import scanner
import open_redirect
import crossref
from spec_analysis import load_and_extract, secured_operations

spec_findings = scanner.scan_paths(["openapi.yaml"])          # Spectral spec-lint
redirect_findings = open_redirect.scan_paths(["src/"])         # Semgrep CWE-601

ops = secured_operations(load_and_extract(Path("openapi.yaml")))
guidance = crossref.render_guidance(ops, "openapi.yaml")       # for the invoking agent
finding = crossref.build_finding(ops[0], "openapi.yaml", "app/routes.py", 42)
errors = crossref.validate_finding(finding)
```

```
python3 scanner.py openapi.yaml
python3 open_redirect.py src/
python3 crossref.py openapi.yaml
```

## Not this module's job

- Generic JWT-bypass/mass-assignment code patterns — 023's job.
- Generic SQLi/XSS/SSRF/Command Injection — 007's job.
- A bespoke per-framework route-to-spec-path matcher — the playbook
  guidance in `crossref.py` is the mechanism, by design (see above).
- Measuring whether an agent following the crossref guidance actually
  catches real bugs — plan 020's job, not something these unit tests
  can claim.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with (from inside this directory):
```
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_open_redirect -v
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_spec_analysis -v
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_crossref -v
```
(macOS/Linux; see the top-level `security-skill/README.md`.)
