# detectors/auth/

AuthN/AuthZ code review — **hybrid**, not a single mechanism: a
deterministic Semgrep-subset detector (`semgrep_detector.py`) for the
narrow patterns Semgrep's registry actually covers well, plus a
**playbook** (`playbook.py`) the invoking AI agent reasons over
directly for everything else. See
`plans/023-authn-authz-code-review-skill.md` and
`meetings/2026-07-22-1500-plan-023-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Why this is hybrid, and why the split isn't even

007 (Code Review — injection classes) wraps Semgrep, which has mature,
broad multi-language rule coverage for SQLi/XSS/SSRF/CmdInj. Verified
at 023's own kickoff that Semgrep's authz/authn coverage is genuinely
patchy: a direct `authorization`/`idor` registry search returned **zero
results for Kotlin, Swift, and Dart**, and only two tangential hits for
Go. Checked again at this implementation, specifically for what
Semgrep *does* cover well: `p/jwt` has real rules for **JS (6), Python
(3), Go (3), Java (3)** — nothing for Kotlin, Swift, Dart, or PHP. So
the deterministic half here is narrow by design (JWT signature/
algorithm bypass only), not a general authz/authn scanner — the
playbook is the *primary* mechanism for this sub-skill, not a fallback
for what Semgrep missed.

## `semgrep_detector.py` — the deterministic half

Built once 007 existed, specifically so its "invoke semgrep, parse
JSON, map to schema" core logic could be reused rather than rewritten
(see plan 023's sequencing note) — that shared logic now lives in
`common/semgrep_wrapper.py`.

- **Config**: `p/jwt` — chosen (not `p/owasp-top-ten`, 007's pack,
  which also happens to catch one of these patterns) as the narrower,
  more clearly-scoped config for this sub-skill, verified via real
  `semgrep --config=p/jwt` runs against synthetic fixtures.
- **`_RULE_ID_OVERRIDES`**: maps specific, individually-verified
  `check_id`s to the *same* ruleId the matching `checklist.json` item
  already uses, so the same underlying weakness gets a consistent
  ruleId regardless of which half (playbook or Semgrep) caught it —
  only `detectorSource` differs. A real nuance found while building
  this table: Semgrep classifies `jwt.decode(verify_signature=False)`
  as **CWE-287** (Improper Authentication) but `algorithms=["none"]` as
  **CWE-327** (Broken/Risky Cryptographic Algorithm) — two distinct
  CWEs for what casually looks like "the same JWT bug." Given a
  distinct ruleId (`auth.jwt-weak-algorithm`, separate from
  `auth.jwt-signature-not-verified`) rather than force-fit into one,
  and CWE-327 added to `knowledge/cwe.json` (plus the OWASP
  Top10:2025 A04 `relatedCwe` crosswalk, verified against OWASP's own
  published mapping) specifically for this.
- Any `check_id` not in the override table (the pack's Go/Java rules
  were counted but not individually triggered/verified here) falls back
  to the generic `auth.{check_id}` naming, same as 007 — still produces
  a valid finding as long as its own metadata resolves in `knowledge/`.

## `playbook.py` — the primary, hybrid-half mechanism

A structured checklist (`checklist.json`, validated against
`checklist.schema.json`) that the *invoking AI agent* reads and reasons
over directly, per CONTEXT.md §1's "agent-native layer that reasons...
the way a security engineer would." This is the only mechanism at all
for Kotlin/Swift/Dart/PHP, and a confirmatory second opinion where
Semgrep also has coverage.

8 items across both weakness classes:

| ruleId | Class | Primary reference | Also caught by `semgrep_detector.py`? |
|---|---|---|---|
| `auth.missing-authentication-check` | broken-authentication | CWE-306 | no |
| `auth.jwt-signature-not-verified` | broken-authentication | CWE-287 | yes (Python) |
| `auth.jwt-weak-algorithm` | broken-authentication | CWE-327 | yes (Python, JS) |
| `auth.session-not-regenerated-after-login` | broken-authentication | CWE-384 | no |
| `auth.missing-authorization-check` | broken-authorization | CWE-862 | no |
| `auth.idor-user-controlled-key` | broken-authorization | CWE-639 | no |
| `auth.client-controlled-privilege-field` | broken-authorization | CWE-863 | no |
| `auth.function-level-authz-missing` | broken-authorization | CWE-862 / API5:2023 | no |

Every reference (CWE and OWASP-ASVS/API-Top10/Top10) is verified to
resolve in `knowledge/` — CWE-287, CWE-306(pre-existing), CWE-327,
CWE-384, CWE-639, and CWE-863 were added there across this plan's two
implementation passes, each verified against `cwe.mitre.org` directly,
not recalled from memory. OWASP Top10:2025 A01/A04/A07's `relatedCwe`
crosswalks were extended too, each verified against OWASP's own
published per-category CWE mapping (`owasp.org/Top10/2025/...`) — same
"authoritative-only" discipline as plan 002.

Each item carries language-specific notes (`languageNotes`) for a
handful of cpmatch's stack languages where a concrete idiom is worth
naming — additive hints, not a filter: an item's core `guidance`
applies regardless of language.

## `subSkill` schema change

`finding.schema.json`'s `subSkill` enum didn't have an `auth` value —
it only had `code-review`. Decided at implementation (user confirmed):
add `auth` as its own value, so policy/reporting can group these
findings separately in the future. Bumped `schemaVersion` 1.0.0 → 1.1.0
in both `finding.schema.json` and `scan-report.schema.json` (their own
documented policy: enum additions require a version bump).

## Usage

```python
import playbook
import semgrep_detector

checklist = playbook.load_checklist()
text = playbook.render_playbook(checklist, language="python")  # or language=None for everything
item = playbook.checklist_item(checklist, "auth.idor-user-controlled-key")
errors = playbook.validate_agent_finding(finding)  # validate an agent-produced finding

findings = semgrep_detector.scan_file(Path("app.py"))  # the deterministic JWT-bypass subset
```

```
python3 playbook.py --language kotlin
python3 semgrep_detector.py path/to/file_or_dir
```

## Not this module's job

- Broader Semgrep-subset coverage beyond JWT bypass — Go/Java rules in
  `p/jwt` weren't individually verified; other authz-adjacent packs
  weren't explored beyond what's documented here.
- Measuring whether an agent following the playbook actually catches
  real bugs, or how often `semgrep_detector.py`'s findings are true
  positives on real code — plan 020 (Test Fixtures)'s job, not
  something these unit tests can claim.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_playbook -v`
and `... test_semgrep_detector -v`
(macOS/Linux; see the top-level `security-skill/README.md`).
