# Race Condition (TOCTOU) — reference

**Playbook-only — no deterministic mechanism.** Unlike Auth/CI-CD
Pipeline's hybrids, semgrep registry coverage for race conditions/
TOCTOU is close to zero registry-wide (checked at this sub-skill's own
kickoff) — there is no `scanner.py`/`semgrep_detector.py` here at all.

Scoped to **TOCTOU-shaped file/resource access only** — not general
race conditions (check-then-act on arbitrary shared state, non-atomic
read-modify-write, missing-lock patterns are explicitly out of scope).

## The playbook (`playbook.py`)

Same shape as `reference/auth.md`'s playbook mechanism — not a script
you run and parse, a checklist *you* (the invoking agent) apply
directly while reading the code.

```
python3 detectors/race-condition/playbook.py --language <the language you're reviewing, e.g. python/go/shell>
```

This prints the checklist as text (4 items: existence-check-then-open,
permission-check-then-use, stat-then-reopen-by-path,
predictable-temp-path — see `checklist.json`). Read it, then manually
inspect the code against each item: a check call (existence/
permission/type) followed by a separate act call on the *same*
file/resource, with no atomic combined operation used instead. When you
find something, construct a `Finding`-shaped dict yourself and validate
it:

```python
import playbook
errors = playbook.validate_agent_finding(finding)
```

**Same legitimate exception as Auth's playbook half** — this is real
detection against a real, versioned checklist, not generic commentary.
No prerequisite tool to be missing; nothing to fall back from.
