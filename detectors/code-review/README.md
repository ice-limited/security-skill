# detectors/code-review/

Injection & Request-Forgery code review: SQL Injection, XSS, SSRF,
Command Injection. See `plans/007-code-review-skill.md` and
`meetings/2026-07-22-1430-plan-007-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Why this wraps Semgrep instead of a from-scratch engine

cpmatch's stack is 13+ languages (Go, Shell, JavaScript, TypeScript,
TSX, Python, Kotlin, Dart, Swift, PHP, Java, HTML, plus CSS/PowerShell
as known gaps). These four vulnerability classes need source→sink
taint tracking, which regex alone can't do reliably (unlike 006's
secret detection, where pattern matching genuinely is sufficient) —
building and maintaining that from scratch per language was never a
realistic MVP. Wraps [Semgrep](https://github.com/semgrep/semgrep) as a
subprocess instead, the same "adapt an existing tool with attribution"
pattern 006 used for gitleaks, one level up (a whole engine, not just
patterns).

**Licenses, verified before committing (not assumed):**
- Semgrep CLI/engine: **LGPL 2.1** — invoking it as a subprocess (how
  this module integrates it) doesn't require this codebase to be LGPL.
- Semgrep community/registry rules: **"Semgrep Rules License v1.0"** —
  permits internal business use (fine for cpmatch's own review use),
  **forbids redistributing the rules or offering them as a service to
  others**. Binding constraint if `security-skill` is ever distributed
  externally — the bundled ruleset (fetched live from the registry via
  `--config`, not vendored into this repo) would need addressing first.

**Windows support is beta** per Semgrep's own docs (`PYTHONUTF8=1`
needed explicitly, `pipx`/`uv` recommended over Homebrew) — a real
external-tool limitation, not something this module's code can fix.

## Shared with detectors/auth/

The subprocess/mapping logic (`run_semgrep()`, severity/confidence
tables, reference extraction, byte offsets, error-level filtering) now
lives in `common/semgrep_wrapper.py`, extracted from this module once
023's Semgrep-subset half (`detectors/auth/semgrep_detector.py`) needed
the same logic — same "shared module once a second consumer exists"
precedent as `common/`'s own origin (plan 005). This module is now a
thin wrapper over it: which rule pack (`p/owasp-top-ten`) and which
subSkill/ruleId namespace (`code-review`). Its public API
(`scan_file`/`scan_paths`/`main`/`ScannerError`) is unchanged by this
refactor — all 27 tests from before still pass without modification
(one test needed its `mock.patch` target updated to point at
`scanner._sw.shutil.which`, since `shutil` itself is no longer imported
directly here).

## Rule pack

`p/owasp-top-ten` (the default `--config`) — chosen empirically, not
assumed: verified by running real `semgrep --config=p/owasp-top-ten`
against synthetic SQLi/Command-Injection/SSRF (Python) and XSS
(JavaScript) fixtures at implementation time and confirming it actually
fires on all four classes. Other candidate packs checked and rejected:
`p/sql-injection` and `p/command-injection` are narrower (miss SSRF/XSS
entirely, by design — they're single-class packs); `p/ssrf` doesn't
exist as a registry config (`rc=7`); `p/default` is a superset with a
couple of extra SQLi-adjacent rules but no additional coverage of the
four in-scope classes. Overridable per call (`scan_paths(..., config=...)`
or `--config` on the CLI) — not hardcoded as the only option.

## Mapping to finding.schema.json — decisions grounded in real Semgrep output, not guessed

Every choice below was derived from actually running Semgrep and
inspecting its JSON output during implementation (see
`plans/007-code-review-skill.md`'s Implementation section for the
exact samples), not from documentation alone:

- **`ruleId`**: `code-review.{check_id}` — Semgrep's `check_id` is
  already lowercase, dot-namespaced (e.g.
  `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`),
  which already satisfies `finding.schema.json`'s `ruleId` regex once
  prefixed — no further slugging needed.
- **Byte offsets**: passed straight through from Semgrep's own
  `start.offset`/`end.offset` — verified these are true UTF-8 byte
  offsets (not character offsets) by testing a fixture with multi-byte
  content before the match. Unlike 006, no manual byte-offset
  computation needed here; Semgrep already does it correctly.
- **Severity**: Semgrep has 3 levels (`ERROR`/`WARNING`/`INFO`) vs. our
  5 (`Critical`/`High`/`Medium`/`Low`/`Info`) — disambiguated using the
  rule's own `metadata.impact` (`HIGH`/`MEDIUM`/`LOW`), since real
  samples showed severity and impact aren't perfectly correlated (e.g.
  `subprocess-shell-true` is `ERROR` severity but `LOW` impact — the
  flag alone isn't dangerous without tainted input reaching it). See
  `scanner._severity()`.
- **Confidence**: Semgrep's own `metadata.confidence`
  (`LOW`/`MEDIUM`/`HIGH`) mapped to `40`/`65`/`85`. A first-pass
  mapping, not empirically calibrated (same caveat as 023's playbook
  confidence tiers).
- **References**: `metadata.cwe` and `metadata.owasp` parsed and
  **filtered to only what resolves in `knowledge/`** — Semgrep's
  `metadata.owasp` lists multiple editions per rule at once (e.g.
  `"A1: Injection"`, `"A03:2021 - Injection"`, `"A05:2025 - Injection"`
  all on one rule); only the `2025`-suffixed entry is ever kept, per
  plan 002's current-edition-only policy. A finding with zero
  recognized references raises `ScannerError` rather than silently
  emitting a reference-less finding (which would fail
  `finding.schema.json`'s `minItems: 1` anyway, with a much less useful
  error).
- **`problem`/`impact`/`recommendation`**: `problem` is Semgrep's own
  `message` field used directly — already a detailed, rule-specific
  description, and this pack has ~80+ distinct `check_id`s, too many to
  hand-author per-rule text the way 006 did for its 8 rules. `impact`
  and `recommendation` are templated from `metadata.vulnerability_class`
  /`likelihood`/`impact`/`references`.
- **Scope filter (`_IN_SCOPE_CWES`)**: `p/owasp-top-ten` is broad, not
  narrowly scoped to this plan's four classes — found for real while
  testing (see plan's Testing pass section) that it also fires on a JWT
  weak-algorithm check (`CWE-327`), which duplicated
  `detectors/auth/semgrep_detector.py`'s own finding for the exact same
  line/byte range under a different ruleId. `scan_paths()` now filters
  its output to only findings citing at least one of `CWE-77/78/79/
  89/918` — an out-of-scope match is another sub-skill's job, not
  silently duplicated here.

## Error handling — verified against real Semgrep behavior, not assumed

- **Nonexistent scanning root** → Semgrep exits **nonzero** (`rc=2`)
  with an `error`-level entry in `errors`. Caught by the return-code
  check. (An earlier check via a shell pipeline through `tail`
  misreported this as `rc=0` — `$?` after a pipe reflects the last
  command, not semgrep's; corrected by checking directly.)
- **One unparseable file in a multi-file scan** → Semgrep exits
  **zero** with a `warn`-level `PartialParsing` entry in `errors`, but
  still returns real results for every file that *did* parse. Verified
  by mixing a syntactically-broken file into a scan directory alongside
  a valid one. **Only `error`-level entries in `errors` raise
  `ScannerError`** — a `warn`-level entry does not discard the good
  results, or a single unrelated broken file would silently zero out an
  entire repo scan's findings.
- **Missing `semgrep` binary** → a clear, actionable `ScannerError`
  (install instructions), not a raw `FileNotFoundError` traceback.

## Usage

```python
from scanner import scan_file, scan_paths

findings = scan_file(Path("app.py"))
findings = scan_paths(["src/"], artifact_type="source-code", config="p/owasp-top-ten")
```

```
python3 scanner.py path/to/file_or_dir [--config p/owasp-top-ten] [--artifact-type source-code]
```

Requires the real `semgrep` CLI on `PATH` (`pip install semgrep`) —
`test_scanner.py`'s subprocess-driving tests skip themselves (not
fail) if it isn't installed, but are never mocked when it is (per the
kickoff's testing discipline: mocking Semgrep's subprocess output would
defeat the point of wrapping a real, external, evolving tool).

## Not this module's job

- File selection/exclusion (which paths get scanned) — orchestration
  concern, same boundary as 006.
- Broken AuthN/AuthZ (023) and Race Condition (024, deferred) —
  split off at this plan's own kickoff.
- Exhaustive per-language validation across all of cpmatch's 13+
  languages — verified for Python and JavaScript at implementation;
  broader coverage is expected but not exhaustively proven yet.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v`
(macOS/Linux; see the top-level `security-skill/README.md`). Windows
Semgrep support itself is beta (see above) — this module's own code
follows the same cross-platform discipline as every other module here
regardless.
