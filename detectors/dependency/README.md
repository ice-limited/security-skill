# detectors/dependency/

CVEs, known-malicious packages, license compliance, and deprecated
packages across lockfiles — via a thin wrapper around the
[osv-scanner](https://github.com/google/osv-scanner) CLI (subprocess),
not hand-written per-ecosystem lockfile parsers. See
`plans/008-dependency-skill.md` and
`meetings/2026-07-22-1700-plan-008-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Why this wraps osv-scanner instead of parsing lockfiles by hand

cpmatch's stack spans 7 package ecosystems (npm, PyPI, Go, Maven,
Packagist, Pub, SwiftURL) — hand-writing and maintaining a lockfile
parser per ecosystem was never realistic. osv-scanner (Google,
**Apache-2.0**, no restrictive rules-license complication like
Semgrep's) already parses all of them and queries
[OSV](https://osv.dev), which itself aggregates GitHub Advisory + PyPI
Advisory + Go vulnerability DB + the **OpenSSF Malicious Packages**
feed. One tool ended up covering all four of this plan's scope items,
each verified for real at kickoff/implementation:

| Scope item | Mechanism | Verified with |
|---|---|---|
| CVE lookup | OSV database via osv-scanner | real npm/Go/PyPI lockfiles |
| Malicious packages | OSV's OpenSSF Malicious Packages feed | a real `MAL-2024-1` entry |
| License compliance | `--licenses <allowlist>` | real npm fixture |
| Deprecated packages | `--experimental-flag-deprecated-packages` | real npm fixture (`request`) |

**Full native Windows/macOS/Linux support** (Scoop/WinGet on Windows) —
no beta caveat, better cross-platform story than 007's Semgrep
dependency.

## Ecosystems

npm, PyPI, Go, Maven (covers both Java and Kotlin — both use Maven/
Gradle coordinates), Packagist (PHP), Pub (Dart), SwiftURL (Swift) —
matches cpmatch's confirmed stack. CSS/HTML/TSX/Shell/PowerShell have
no package-manager "dependencies" in this sense — not a gap, just not
applicable. Verified end-to-end (real, tool-generated lockfiles run
through the actual detector) for npm, Go, and PyPI; Maven/Packagist/
Pub/SwiftURL were checked against OSV's raw API at kickoff but not yet
run through osv-scanner itself with a real project.

## License policy

No cpmatch org-approved/denied dependency license list exists yet
(kickoff decision) — defaults to a **permissive-only baseline**
(`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`). Override via
`scan_paths(..., license_allowlist=(...))` once a real policy exists.

## Mapping to finding.schema.json — decisions grounded in real osv-scanner output

- **Four distinct `ruleId`s**: `dependency.cve`, `dependency.malicious-package`
  (any vulnerability id prefixed `MAL-`), `dependency.deprecated-package`,
  `dependency.license-violation` — so policy/reporting can treat these
  differently if needed.
- **Severity**: prefers the vulnerability's own qualitative
  `database_specific.severity` (`CRITICAL`/`HIGH`/`MODERATE`/`LOW`,
  direct mapping); falls back to banding the enclosing group's numeric
  `max_severity` CVSS score against the **official CVSS v3.1
  qualitative rating scale** (verified against first.org's
  specification document: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9
  Medium, 0.1-3.9 Low, 0.0 Info) when the qualitative field is absent;
  defaults to Medium if neither is available. Malicious-package
  findings are always `Critical` (same precedent as 006's secret
  detector — if it's real, it's always bad, regardless of any other
  signal).
- **Confidence**: CVE findings get a higher confidence
  (`_CVE_REVIEWED_CONFIDENCE`) when `database_specific.github_reviewed`
  is true, lower otherwise; malicious-package findings get high
  confidence (curated OpenSSF feed, not a heuristic); deprecated-package
  findings get a *lower* confidence ceiling — osv-scanner itself marks
  that feature experimental; license-violation findings get high
  confidence (deterministic string match against an allowlist).
- **References**: CVE findings use `database_specific.cwe_ids` (filtered
  to what resolves in `knowledge/`), falling back to **CWE-1395**
  ("Dependency on Vulnerable Third-Party Component") when a vulnerability
  cites no CWE at all. Malicious-package findings cite **CWE-506**
  ("Embedded Malicious Code"). Deprecated-package and license-violation
  findings both cite **CWE-1104** ("Use of Unmaintained Third Party
  Components") — decided at implementation: license violations are a
  legal/compliance concept with no naturally-fitting CWE of their own,
  and `finding.schema.json`'s `references[]` only supports security
  standards, so CWE-1104 is reused as the closest fit rather than
  adding a new non-security reference concept to the schema. Every
  finding also cites **OWASP-Top10 A03:2025** ("Software Supply Chain
  Failures") — verified as OWASP's own current-edition category for
  this whole domain (its official CWE mapping includes CWE-1104 and
  CWE-1395, confirmed against `owasp.org/Top10/2025/...`).
- **Location**: unlike 006/007's precise byte/line locations in source
  code, a lockfile has no one stable "the vulnerable line" — a package
  can appear as a transitive dependency in multiple places, and
  osv-scanner's own output is package-name+version granular, not
  line-granular. `location` points at the lockfile's file path with
  placeholder `startLine`/`endLine` (both `1`) rather than a misleadingly
  precise lookup.

## `--recursive` is always passed — a real bug found in testing, not theoretical

Found during the "test plan 008" round: without `--recursive`,
osv-scanner only looks for lockfiles directly in the given path(s), not
in subdirectories — so pointing this at a repository root whose
lockfile lives one level down (e.g. a `backend/` subfolder, an
extremely common real layout) silently found **nothing**, a false "no
vulnerabilities" rather than a crash. Confirmed by scanning
`testdata/nested-repo/` (the same known-vulnerable lockfile as
`npm-vulnerable/`, one directory deeper) both with and without the
flag; mutation-tested by removing it again — the regression test
correctly failed. Also verified in the same round: a syntactically
corrupted lockfile alongside a valid one does **not** prevent
osv-scanner from still reporting the valid sibling's real findings
(mirrors 007's partial-parse-failure discipline, confirmed here rather
than assumed to carry over from a different tool) — see
`testdata/mixed-with-corrupted/`.

## Error handling — verified against real osv-scanner behavior, not assumed

osv-scanner's exit code does **not** reliably distinguish "scanned
cleanly, no findings" from "scanned cleanly, findings present" —
verified at kickoff: the exact same vulnerable package returned `rc=0`
in one run and `rc=1` in an otherwise-identical run, and manifest-file
scans (`go.mod`, `requirements.txt`) returned `rc=0` even with dozens
of vulnerabilities present. **Only a return code outside `{0, 1}` is
treated as a real invocation failure** (confirmed for real: `rc=127`
for a bad path or unknown flag). `--allow-no-lockfiles` is always
passed so a directory with no recognized lockfile returns an empty
result rather than the tool's own `rc=128` "nothing to scan" error —
scanning an arbitrary directory that genuinely has no dependencies
isn't a failure.

A mutation-testing round caught a real test-quality gap here: the
initial `test_bad_path_raises_scanner_error` passed even after removing
the return-code check, because a bad path also produces empty stdout,
which independently fails JSON parsing and raises `ScannerError` for an
unrelated reason. Fixed by adding a test that mocks `subprocess.run` to
return valid JSON alongside a bad return code, isolating the
return-code check specifically.

## Usage

```python
from scanner import scan_file, scan_paths

findings = scan_paths(["path/to/repo"])                 # scans for all lockfiles under a directory
findings = scan_file(Path("requirements.txt"))
findings = scan_paths(["."], license_allowlist=("MIT",)) # override the default allowlist
```

```
python3 scanner.py path/to/project [--artifact-type package-lock] [--data-source native]
```

Requires the real `osv-scanner` CLI on `PATH`
(`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`,
`brew install osv-scanner`, or a prebuilt binary/Scoop/WinGet on
Windows) and network access to query OSV.
`test_scanner.py`'s subprocess-driving tests skip themselves (not fail)
if it isn't installed, but are never mocked when it is (per 007's
testing discipline: mocking an external, evolving tool's output would
defeat the point of wrapping it).

## Test fixtures (`testdata/`)

All lockfiles here are **real**, generated by the actual package
managers (`npm install`, `go get`), not hand-typed approximations — a
hand-crafted `package-lock.json` was found at kickoff to behave
differently from a real one in some cases (mismatched exit codes),
so only real, tool-generated fixtures are used for testing:

- `npm-vulnerable/` — real `npm install lodash@4.17.15`
- `npm-clean/` — real `npm install is-odd@3.0.1` (no known issues)
- `npm-deprecated/` — real `npm install request@2.88.2` (deprecated by
  its own maintainer)
- `npm-malicious/` — a synthetic lockfile referencing a real, confirmed
  OSV malicious-package entry (`squaredev-next-online-payments-example`
  `99.0.0`, `MAL-2024-1`) — this one is necessarily hand-assembled since
  the package was never real/installable, but the vulnerability record
  itself is real and independently verified via the OSV API.
- `go-vulnerable/` — real `go get golang.org/x/crypto@...` + `go mod tidy`
- `pypi-vulnerable/requirements.txt` — a plain-text `requirements.txt`
  pin, which doesn't have the lockfile-structure fragility
  `package-lock.json` does.
- `nested-repo/backend/` — the same vulnerable lockfile as
  `npm-vulnerable/`, one directory deeper, added to regression-test the
  `--recursive` bug found in the "test plan 008" round.
- `mixed-with-corrupted/` — a valid lockfile (`good/`) alongside a
  syntactically-broken one (`bad/`), added to confirm one corrupted
  file doesn't discard a sibling's real findings.

## Not this module's job

- File selection/exclusion (which paths get scanned) — orchestration
  concern, same boundary as every other detector here.
- SBOM generation and image signing — 014 (Supply Chain).
- Exhaustive per-ecosystem validation beyond npm/Go/PyPI (Maven,
  Packagist, Pub, SwiftURL checked against OSV's raw API only).
- Whether osv-scanner's experimental deprecated-package flag is stable
  enough for production use long-term — shipped in v1 per kickoff
  decision, with a lower confidence ceiling reflecting that caveat.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v`
(macOS/Linux; see the top-level `security-skill/README.md`).
