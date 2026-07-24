# Manual Test Log — AGENTS.md Adapter (plan 018)

Per มิ้นท์'s point at kickoff: `AGENTS.md` has no discrete "did it
trigger" event the way a Claude Code Skill does — it's always-on
ambient context. The useful test is "given this file, does an agent
actually follow it and invoke a real detector," not "did it get
discovered."

## An honest caveat on what this test actually verifies

The agent used to run this test is Claude-based (this harness's own
general-purpose subagent), not literally Codex, OpenCode, or Cursor —
those tools aren't invokable from here. What *is* verified: the
`AGENTS.md` convention itself is just a markdown file concatenated into
an agent's ambient context (per the spec researched at kickoff — "the
agent simply parses the text you provide," no special runtime), so an
LLM agent given this content in context and asked to follow it is a
reasonable proxy for the mechanism every AGENTS.md-convention tool
actually uses. It is **not** a verification of Codex/OpenCode/Cursor's
own specific harness behavior (tool-calling quirks, permission prompts,
etc.) — that would need a real session in one of those tools.

## Setup

A scratch git repo (outside both `security-skill-workspace/` and
`security-skill/`) with `AGENTS.md` (this plan's content) at its root
and a fixture `Dockerfile`:

```dockerfile
FROM ubuntu:latest
USER root
RUN curl -sSL https://example.com/install.sh | bash
ENV DB_PASSWORD=SuperSecretPassw0rd123
```

Deliberately used a different secret shape than 017's own manual test
(which accidentally used AWS's own allowlisted documentation example
key and got a false negative) — verified independently, before running
the agent, that `detectors/secret/scanner.py` actually flags this value
(`secret.generic-api-key`, Critical) so this test could observe a real
true positive, not repeat the same accidental miss.

A fresh agent session (no memory of this plan) was asked to do a
security review of the Dockerfile, told to follow the repo's own
`AGENTS.md` the way any AGENTS.md-convention agent would.

## Result

**1. Did AGENTS.md get read, and did it shape behavior?** Yes — read
before doing anything else, and its instructions drove the whole
approach: use the Secret/Docker detectors under `detectors/` rather
than eyeballing the file, treat commands as relative to a
`security-skill/` checkout, and — critically — ask the user rather than
search the filesystem if that checkout isn't a sibling.

**2. Was a real detector actually invoked?** Yes:
`python3 detectors/secret/scanner.py Dockerfile --artifact-type dockerfile`,
executed via Bash, not a dry run.

**3. What happened when the path failed to resolve (no `security-skill/`
checkout in the scratch repo), and was it handled honestly?**

**This is the one real improvement over 017's own manual test, applied
proactively rather than discovered the hard way again**: 017's test
found that an agent will autonomously search the filesystem for a
`security-skill/` checkout instead of asking, when the instruction to
ask wasn't emphatic enough — that finding was folded into `AGENTS.md`'s
content here from the start (the "ask the user... rather than
searching the filesystem for one" language). Result: this agent hit the
exact same failure mode (`Errno 2: No such file or directory`, no
`security-skill/` anywhere under the scratch repo, confirmed via its own
`find`), and **did not** search the filesystem or fall back to a
self-authored review — it stopped and asked the user for the real
checkout path, exactly as instructed.

**Follow-up run, given the real path**: re-invoked both detectors
against the fixture. **Secret detector**: 1 real finding,
`secret.generic-api-key` (Critical, confidence 60) on the
`DB_PASSWORD` line — a genuine true positive this time, unlike 017's
accidental false negative. **Docker detector**: 4 real findings —
`docker.unpinned-base-image` (Medium), `docker.root-user` (High),
`docker.missing-healthcheck` (Low), `docker.curl-pipe-shell` (High) —
matching the fixture exactly. All reported as real, structured output,
not invented commentary.

## Net conclusion

The content correctly shapes agent behavior end-to-end: real detector
invocation, real structured findings, and the path-resolution failure
mode handled correctly (ask, don't search) on the first try — because
017's own hard-won finding was applied here proactively instead of
needing to be rediscovered. The caveat above (this tests the AGENTS.md
mechanism generically, not Codex/OpenCode/Cursor's own specific
harnesses) stands as a real, acknowledged limit of what this log can
claim.
