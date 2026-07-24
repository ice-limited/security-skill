# detectors/race-condition/

Race Condition (TOCTOU) code review — **playbook-only, no deterministic
scanner**. See `plans/024-race-condition-code-review-skill.md` and
`meetings/2026-07-22-1600-plan-024-kickoff.md` (original kickoff,
deferred past Phase 1) /
`meetings/2026-07-25-1100-plan-024-kickoff.md` (reopening kickoff,
overrode the deferral) in the security-skill-workspace repo for design
rationale.

## Why this is playbook-only, unlike 013/023's hybrids

007 (Code Review — injection classes) and 023 (AuthN/AuthZ) both wrap
Semgrep for a real, if sometimes narrow, deterministic subset. This
sub-skill doesn't — checked at the original 2026-07-22 kickoff:
`race-condition` returns 0 hits registry-wide, `toctou` returns 2 (one
OCaml-only rule, one metadata file), quoted `"race condition"` returns
3 (adding one Solidity-specific reentrancy rule) — across *all* 30+
languages Semgrep supports, not just cpmatch's stack. Maintaining a
"deterministic" module for 2-3 barely-useful rules would add real
maintenance surface without real detection value, so there's no
`scanner.py`/`semgrep_detector.py` here at all — `playbook.py` is the
only mechanism, not a supplement to one.

## Why this is scoped to TOCTOU only, not general race conditions

The original stub's scope ("check-then-act without locking,
TOCTOU-shaped file/resource access, non-atomic read-modify-write on
shared state, etc.") was narrowed at the reopening kickoff. วิน's
reasoning: TOCTOU (a check call followed by an act call on the same
file/resource, without an atomic combined operation in between) is the
one race-condition shape genuinely amenable to static, syntactic
pattern-matching — general concurrency bugs (missing locks, non-atomic
shared-state mutation) need real data-flow/interleaving analysis a
playbook-reading agent can't reliably do either, so narrowing to TOCTOU
isn't just noise reduction, it's picking the one sub-case where a
checklist has a real chance of being accurate.

## `checklist.json` — 4 items, all TOCTOU-scoped

- `race-condition.toctou-file-existence-then-open` — existence check
  (`os.path.exists`, `test -f`) then non-atomic open/create.
- `race-condition.toctou-permission-check-then-use` — the canonical
  CWE-367 `access()`-then-`open()` pattern, warned against by name in
  multiple languages' own standard library docs.
- `race-condition.toctou-stat-then-operate-on-path` — `stat`/`lstat` by
  path to check type/identity, then a separate re-open by the same path
  string instead of continuing to use an already-open handle (symlink
  swap window).
- `race-condition.toctou-predictable-temp-path` — a predictable
  temp-file/dir name in a shared location, instead of a platform secure
  temp-file API (`tempfile.mkstemp()`, `mktemp`, etc.).

Every item cites `CWE-367` (Time-of-check Time-of-use Race Condition —
added to `knowledge/cwe.json` specifically for this plan; the more
general `CWE-362` was already seeded from 007's own kickoff) alongside
it. No `OWASP-Top10` reference forced onto any item — OWASP's official
2025 category mappings (checked against `knowledge/owasp-top10.json`'s
already-curated `relatedCwe` subsets) don't cleanly assign race
conditions to a specific Top 10 category; citing `CWE` alone here
follows the same "don't force a reference that doesn't fit" precedent
023's `auth.session-not-regenerated-after-login` item and 014's
NIST-SSDF-only supply-chain findings already established.

## `playbook.py` — the only mechanism

Same shape as `detectors/auth/playbook.py`: `load_checklist()`
validates against `checklist.schema.json`; `render_playbook(checklist,
language=None)` renders guidance text (generic guidance plus that
language's notes, if any); `checklist_item()` looks up one item by
`ruleId`; `validate_agent_finding()` validates an agent-produced
finding against the real `finding.schema.json`.

`finding.schema.json`'s `subSkill` enum gained `race-condition`
(schemaVersion 1.2.0 → 1.3.0, same bump-on-enum-addition policy 023/013
exercised for `auth`/`cicd-pipeline`).

## Fixtures — paired vulnerable/false-positive, per มิ้นท์'s point

A playbook-only sub-skill has no deterministic tool run to validate
findings against, so `test_playbook.py`'s `ToctouFixtureTests` encodes,
in test form, exactly what "matches this checklist item" vs. "already
uses the atomic-safe equivalent" means for each of the 4 items — a
vulnerable snippet and a paired false-positive (atomic-equivalent)
snippet, asserted to actually differ and to use the specific safe
pattern (`O_EXCL`, catching `PermissionError`, `fstat` on an open
handle, `mkstemp`) each item's own guidance points to. See
`docs/testing-standards.md` (020) for why this pairing matters for
every sub-skill that touches a real-world-shaped pattern, not just this
one.

## Usage

```python
import playbook

checklist = playbook.load_checklist()
text = playbook.render_playbook(checklist, language="python")  # or language=None for everything
item = playbook.checklist_item(checklist, "race-condition.toctou-file-existence-then-open")
errors = playbook.validate_agent_finding(finding)  # validate an agent-produced finding
```

```
python3 playbook.py --language python
```

## Not this module's job

- Any deterministic scanner — confirmed at both kickoffs, there's no
  real registry coverage to wrap.
- General (non-TOCTOU) race conditions: check-then-act on arbitrary
  shared state, non-atomic read-modify-write, missing-lock patterns —
  explicitly out of scope for v1, not silently folded in.
- Dynamic analysis (running tests under a race detector like Go's
  `-race`) — ก้อง's point at both kickoffs: a structurally different
  integration shape than every other detector in this repo, a future
  plan's job if ever pursued.
- Measuring whether an agent following the playbook actually catches
  real bugs on real code — plan 020 (Test Fixtures)'s retrofit didn't
  produce race-condition-specific fixtures (this plan's own reopening
  overrode that unmet precondition); this module's own paired
  synthetic fixtures are what exist today.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_playbook -v`
(macOS/Linux; see the top-level `security-skill/README.md`).
