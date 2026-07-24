# Testing Standards

This document formalizes, as an explicit checklist, the testing
standard that already emerged in practice across plans 001–019 without
ever being written down centrally — see
`plans/020-test-fixtures-evaluation-corpus.md` and
`meetings/2026-07-25-1000-plan-020-kickoff.md` in the
security-skill-workspace repo for how this plan came to be a retrofit
rather than an up-front design. Nothing here is new policy; it's a
record of what "done" has actually meant for every plan so far, so the
next plan doesn't have to rediscover it from 15+ kickoff notes.

## 1. Fixtures are synthetic, and live inline

Every sub-skill's test fixtures are small, hand-written, obviously-fake
snippets (`FROM ubuntu:latest`, `AKIA...EXAMPLE`-shaped strings, toy
Terraform blocks) embedded directly as string literals in that
sub-skill's own `test_*.py` — not sourced from a public vulnerable-app
corpus (OWASP Benchmark, WebGoat, etc.), and not kept in a separate
fixtures repository. Two reasons this held up in practice, not just in
theory:

- Real-world validation comes from invoking the actual external
  scanning tool (Semgrep, Trivy, Checkov, OSV-Scanner, Scorecard)
  against these synthetic fixtures — the "is this a real class of
  vulnerability" question is answered by the real tool's own
  well-established rule coverage, not by how the fixture was sourced.
- Every fixture is obviously synthetic (fake key values, placeholder
  resource names), so there's no real secret/sensitive-data handling
  concern that would justify a separate, access-restricted repo.

Adopting a public corpus (OWASP Benchmark/WebGoat) remains a real,
legitimate future enhancement — flagged and deferred at 020's own
kickoff, not silently ruled out.

## 2. Every real-external-tool wrapper needs a false-positive corpus too

Any sub-skill that wraps a real external tool (Semgrep/Trivy/Checkov/
OSV-Scanner/Scorecard) includes fixtures that intentionally *resemble*
a vulnerable pattern but are legitimate — not just vulnerable-pattern
fixtures. Established explicitly in secret (006), docker (009), and
supply-chain (014)'s own test suites; the same discipline should extend
to any future sub-skill wrapping a new external tool.

## 3. Never mock the real external tool's own behavior

Tests that exercise a real external CLI (Semgrep, Trivy, Checkov,
OSV-Scanner, Scorecard, Helm) invoke the real binary — they never mock
its output wholesale. Subprocess-driving tests use
`@unittest.skipUnless(<tool>_available(), "requires the real <tool> CLI on PATH")`
to skip themselves (not fail) when that real CLI isn't installed, so
the suite stays runnable without every external tool present, without
ever pretending a mocked response is equivalent to a real scan.

**Narrower exception, and where it can go wrong**: a wrapper module's
own *argument-passing and output-normalization* logic (e.g.
`common/checkov_wrapper.py`'s `run_checkov()`) is reasonably tested by
mocking `subprocess.run` itself, since that's testing this project's
own code, not the external tool's behavior. **Real gap found while
building this plan's evaluation harness**: those mocked tests
(`common/test_checkov_wrapper.py`, `detectors/iac/test_scanner.py`)
still call the wrapper's own `_check_checkov_available()` gate first,
which checks the real `PATH` via `shutil.which` — so they fail, not
skip, in any shell where the tool isn't actually on `PATH`, even though
the mock means they never actually need it. `run_all_tests.py` works
around this by invoking tests through the same interpreter this
project's own `.venv` provides, with its `bin/` prepended to `PATH` (an
explicit activation-equivalent step, not implicit) — but a contributor
running one of these two files directly, in a shell that hasn't
activated the venv, will still see this. Not fixed at the source in
this retrofit (the checkov-availability gate itself is arguably
correct — a real caller should be told the tool is missing) — noted
here as a known, real rough edge for a future pass, not silently
hidden.

## 4. Mutation-test every regression-guard test

A test written specifically to catch a real bug (not just to exercise
a code path) is verified by temporarily reverting the fix and
confirming the test actually fails, then restoring it. Applied
throughout 015–019's own manual and automated tests alike — e.g. 015's
secret byte-range fix, 016/017/018's coverage guards. A test that would
pass whether or not the bug it claims to guard against is present isn't
real coverage.

## 5. Cross-platform verification is a standing check, not a one-time audit

Every suite is runnable under both the normal locale and a forced
non-UTF-8 locale (`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII`), per
plan 022 — documented per-directory in each README, re-run whenever new
file I/O is added, not just verified once at 022's own implementation.

## 6. Running everything together

`security-skill/run_all_tests.py` (plan 020) discovers and runs every
`test_*.py` in the repo, reporting a per-directory pass/fail/skip
summary and exiting non-zero only on a real failure or error — a skip
because a real external tool isn't installed never fails the run.
Prefers this repo's own `.venv` (with its `bin/` prepended to `PATH`,
per the point in §3 above) if present.

```
python3 run_all_tests.py [--verbose]
```
