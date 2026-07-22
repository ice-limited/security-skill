# policy/

Severity → action decision logic. Pure logic, no CI/pipeline dependency
— see `plans/003-policy-engine.md` and
`meetings/2026-07-22-1214-plan-003-kickoff.md` in the
security-skill-workspace repo for design rationale. Deliberately
separate from actually enforcing a verdict (GitHub Actions/GitLab
CI/Jenkins wiring — that's plan 016).

## Files

- `policy.schema.json` — JSON Schema for a policy config. Requires all 5
  severities (`Critical`/`High`/`Medium`/`Low`/`Info`) mapped to an
  action from a fixed enum (`block-merge`/`require-review`/
  `create-ticket`/`notify`/`none`) — no silent gaps.
- `default-policy.json` — the shipped default, matching CONTEXT.md §9
  (Critical→block-merge, High→require-review, Medium→create-ticket,
  Low→notify, plus Info→none).
- `engine.py` — `evaluate(findings, policy)` / `evaluate_report(report,
  policy)` and `resolve_policy(repo_root=None)`.
- `validate.py` — schema conformance check for a policy file.
- `test_engine.py` — test suite.

## Usage

```python
from engine import resolve_policy, evaluate_report

policy = resolve_policy(repo_root="/path/to/target/repo")
result = evaluate_report(scan_report, policy)
# {"perFinding": [{"findingId", "severity", "action"}, ...],
#  "aggregateAction": "block-merge"}
```

```
python3 engine.py path/to/scan-report.json [--repo-root /path/to/repo]
```

## Per-repo override

A target repo may carry **`.security-skill/policy.json`**, validated
against the same schema and used **wholesale in place of** the default —
not deep-merged. Because the schema requires every severity to be
present, a repo override is always a complete, self-contained policy; an
invalid override raises rather than silently falling back to the
default (fail loud — a broken override is a config bug to fix, not to
paper over).

## Not this module's job

- Deciding which individual findings get suppressed (plan 004) — this
  module only respects the `suppressed` flag already on a finding.
- Actually blocking a merge, opening a ticket, or notifying anyone (plan
  016) — this module only computes what *should* happen.
- Per-`subSkill`/`artifactType` policy granularity — deferred, not
  building for a hypothetical need (see plan 003's Scope).
