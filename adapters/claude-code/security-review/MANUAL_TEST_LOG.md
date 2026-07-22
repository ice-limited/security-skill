# Manual Test Log — `security-review` Skill (plan 017)

Per มิ้นท์'s point at kickoff: whether Claude actually decides to
invoke this skill isn't something a unit test can prove — it needs a
real, human-observed session. This is that log.

## Setup

A scratch git repo (outside both `security-skill-workspace/` and
`security-skill/`) with one fixture file, `Dockerfile`:

```dockerfile
FROM ubuntu:latest
USER root
RUN curl -sSL https://example.com/install.sh | bash
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
```

`security-review/` (this skill) **copied** (not symlinked — deliberately
testing the harder of the two supported install paths) into that
scratch repo's `.claude/skills/`. A fresh agent session (no memory of
this plan, no hints about which tool/skill to use) was asked to "do a
security review of the Dockerfile in this repo."

## Result

**1. Did the skill get discovered?** Yes, automatically — it appeared
in that session's own skill listing with the description this plan
wrote, and shaped what the agent did next without being told to use it
by name.

**2. Was a real detector actually invoked, or did it just read-and-reason?**
Real detectors were invoked via Bash, twice each:
`detectors/docker/scanner.py` and `detectors/secret/scanner.py`.

**3. What happened with the copied (non-symlinked) install's relative
paths, and was it handled honestly?**

Both commands failed exactly as anticipated
(`No such file or directory`, since `detectors/` doesn't exist relative
to a standalone scratch repo). The agent then deviated from `SKILL.md`'s
instruction at the time (which said "ask the user where their
`security-skill/` checkout lives") — instead of asking, it searched the
filesystem on its own initiative, found this machine's real
`security-skill-workspace/security-skill` checkout, and re-ran both
detectors from there. It disclosed this deviation candidly rather than
presenting it as compliant. **Real gap found and fixed as a direct
result of this test**: `SKILL.md`'s "Locating `security-skill/`"
section now states explicitly *why* guessing is unsafe (a filesystem
search could land on the wrong checkout — different clone, branch, or
even a different project entirely — and silently run code the user
never pointed at), not just "ask instead."

**Docker detector**: ran successfully against the real checkout and
returned 4 real, correctly-structured findings —
`docker.unpinned-base-image` (Medium), `docker.root-user` (High),
`docker.missing-healthcheck` (Low), `docker.curl-pipe-shell` (High) —
each with problem/impact/recommendation/CWE-OWASP references and
`detectorSource: docker-trivy-wrapper`. Matches the fixture exactly
(`FROM ubuntu:latest`, `USER root`, `curl | bash`, no `HEALTHCHECK`).

**Secret detector**: ran successfully (exit 0) but returned `[]` — no
finding for the `AKIAIOSFODNN7EXAMPLE` value. **Investigated this
independently (not just taken on the sub-agent's word) before writing
it down**: this is *not* a detector bug. `detectors/secret/scanner.py`
has an explicit, documented allowlist
(`_KNOWN_PLACEHOLDER_VALUES` in `scanner.py`) that excludes
`AKIAIOSFODNN7EXAMPLE` by name, because it's AWS's own published
documentation example access key — a deliberate false-positive
guard, not a gap. The fixture above accidentally used the one AWS
access-key value this project's own detector is specifically designed
to ignore. Re-verified the regex itself matches the value fine in
isolation (`re.findall` against the raw pattern) — confirming the
allowlist, not a pattern bug, is what suppressed it. A follow-up
manual run with a non-placeholder-shaped fixture value would be needed
to observe a true-positive secret finding end-to-end; not done here
since the false negative traced to a real, intentional, already-correct
design decision, not something this plan needed to fix.

## Net conclusion

The skill triggers correctly, invokes real detectors (not a
self-authored review), surfaces path-resolution failures rather than
silently falling back, and this test's own findings led to one real
`SKILL.md` wording fix (don't autonomously search the filesystem for a
`security-skill/` checkout). Acceptance criteria from the plan/kickoff
are met for the two detectors exercised (Docker, Secret); the other 8
sub-skills' reference docs are structurally verified by
`test_skill_structure.py` but have not each had their own live
human-observed run — reasonable for an MVP per พิม's own scope note at
kickoff, not silently glossed over here.
