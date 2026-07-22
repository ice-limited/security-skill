# decision/

Sits between raw detector output (`../schema/finding.schema.json`) and
the policy engine (`../policy/`) — see `plans/004-decision-layer-scoring.md`
and `meetings/2026-07-22-1304-plan-004-kickoff.md` in the
security-skill-workspace repo for design rationale.

## What this does

1. **Exact-duplicate dedup** — collapses findings with the same `ruleId`
   + same `location` to one, keeping the first occurrence. "Same
   location" includes `startByte`/`endByte` when a detector provides
   them, not just `file`/`startLine`/`endLine` — two distinct findings
   from the same rule can legitimately share a line (e.g. two different
   hardcoded secrets on one line); falls back to line-range-only when
   neither finding has byte info. Cross-detector fuzzy dedup (different
   rules flagging what might be the same underlying issue) is
   explicitly deferred — no real sub-skill detectors exist yet to design
   that matching rule against.
2. **Exception-based suppression** — a target repo may carry
   **`.security-skill/exceptions.json`**, keyed by `findingId` (must be
   unique per file — a repeated `findingId` is a config error, not
   silently resolved). A matching, non-expired exception sets
   `suppressed=true` and `suppressionReason` on that finding. Entries
   may carry an optional `expiresAt` (ISO 8601 date, inclusive — valid
   through and including that date, same convention as a credit card's
   "valid thru") so a "temporary" suppression can't silently become
   permanent.

## What this deliberately does NOT do

- **Confidence calibration.** `calibrate_confidence()` is currently an
  identity function — the plug-in point for a real model exists, but no
  detector has produced real true-positive/false-positive signal yet to
  calibrate one against. Building a model against zero data would be
  calibrating against nothing.
- **Inline code comment suppression** (`# nosec`-style). Rejected at the
  kickoff: security-skill's scope spans many artifact types with
  different comment syntax (Python/Shell `#`, JS/Java/Go `//`,
  HTML/YAML `<!-- -->`, Terraform HCL, Dockerfile...) — a correct
  per-language parser is real, duplicated complexity for a mechanism the
  centralized file handles uniformly and more auditably.
- **Policy → action mapping.** That's `../policy/` — 004 only produces
  the `suppressed` flag policy reads.

## Usage

```python
from decision import process_report

result = process_report(scan_report, repo_root="/path/to/target/repo")
# same ScanReport shape, `findings` deduped + suppressions applied
```

```
python3 decision.py path/to/scan-report.json [--repo-root /path/to/repo]
```

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly, and
`decision.py`/`validate.py` reconfigure stdout/stderr to UTF-8 (plan
022). Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_decision -v`
(macOS/Linux; see the top-level `security-skill/README.md`).
