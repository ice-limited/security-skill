# Auth (AuthN/AuthZ) — reference

**Hybrid** — two distinct mechanisms, both real, not one deterministic
scanner. Run both; they cover different weaknesses.

## Mechanism 1 — deterministic (`semgrep_detector.py`)

```
python3 detectors/auth/semgrep_detector.py path/to/file_or_dir
```

Narrow by design: JWT signature/algorithm bypass only (`p/jwt` config).
Requires the real `semgrep` CLI on `PATH` (`pip install semgrep`) — if
missing, relay the error verbatim per `SKILL.md`'s hard rule, then still
run Mechanism 2 below (it doesn't depend on semgrep).

Output: a JSON array of `Finding` objects on stdout.

## Mechanism 2 — the playbook (`playbook.py`)

This one is **not** a script you run and parse — it's a checklist
*you* (the invoking agent) apply directly while reading the code, for
everything Semgrep's registry doesn't cover well (verified at 023's own
kickoff: zero Semgrep authz/idor results for Kotlin, Swift, Dart; only
two tangential Go hits).

```
python3 detectors/auth/playbook.py --language <the language you're reviewing, e.g. python/kotlin/go>
```

This prints the checklist as text (IDOR, missing authz checks, broken
access control patterns, etc. — see `checklist.json`). Read it, then
manually inspect the code against each item. When you find something,
construct a `Finding`-shaped dict yourself (same fields as any other
detector's output — `title`/`problem`/`impact`/`recommendation`/
`references`/`severity`/`confidence`/`location`) and validate it:

```python
import playbook
errors = playbook.validate_agent_finding(finding)
```

**This is the one legitimate case where you construct a finding
yourself rather than parsing a script's output** — it is still real
detection against a real, versioned checklist, not generic commentary;
that's why `SKILL.md`'s hard rule says "invoke the real detector," and
the playbook *is* the detector here, just one whose "invocation" is you
reading a checklist instead of a script producing JSON.
