# adapters/agents-md/

The AGENTS.md-convention adapter (plan 018) — Codex, OpenCode, Cursor,
and any other tool that reads a repo-root `AGENTS.md` per the
[agents.md](https://agents.md/) spec. See
`plans/018-agents-md-adapter.md` and
`meetings/2026-07-24-1000-plan-018-kickoff.md` in the
security-skill-workspace repo for design rationale.

## `AGENTS.md` — one flat file, no sibling references

Unlike `adapters/claude-code/` (plan 017), this content is **one file**,
not a router plus reference docs. `AGENTS.md` has no progressive-
disclosure mechanism — per the spec, "the agent simply parses the text
you provide," no sibling-file loading — so all per-sub-skill detail
(detector command, prerequisite tool) lives in one table inside the
file itself.

**Real research, not the original stub's assumption**: Cursor's current
Agent mode reads `AGENTS.md` natively (including nested subdirectory
files); the legacy `.cursorrules` format isn't loaded in Agent mode at
all. `.cursor/rules/*.mdc` is a real, separate mechanism for
glob-scoped conditional activation and token budgeting — a genuine
future enhancement, not a gap this content needs to close. See the
kickoff meeting note for the full research.

## Distribution: append, don't drop in

Unlike a Claude Code Skill (its own isolated directory under
`.claude/skills/`), `AGENTS.md` is a single repo-root file most repos
already use for their own project instructions. **Copy this file's
content as a section into your own repo's `AGENTS.md`** — don't
overwrite an existing one. The content is wrapped in an HTML comment
explaining this at the top of the file itself.

## Hard rule carried over from 017, made more prominent here

Same requirement วิน raised at 017's kickoff and reiterated at this
plan's: always invoke the real detector and report its real structured
output, never substitute general judgment when a detector or its
prerequisite is unavailable. Here it's stated directly in the one file
an agent reads (no reference doc to bury it in).

## `test_agents_md_structure.py` — what's automatable

There's no frontmatter or discovery-trigger to check the way 017's
`SKILL.md` has (`AGENTS.md` has none) — what this suite checks instead:
the hard-rule language is present, every `finding.schema.json` subSkill
has its detector command referenced (no silent coverage gaps), and the
"ask, don't search the filesystem" instruction (see below) is present.

```
python3 -m unittest test_agents_md_structure -v
```

## `MANUAL_TEST_LOG.md` — a real run, with an honest caveat

`AGENTS.md` has no "did it trigger" moment to observe — the test is
"does an agent given this content actually follow it." Run against a
scratch repo with a genuine secret + Docker misconfiguration fixture;
real detector invocation and real findings confirmed. **One real
improvement over 017's own manual test, applied proactively**: 017's
run found that an agent will autonomously search the filesystem for a
`security-skill/` checkout instead of asking, when the instruction to
ask isn't emphatic enough. That finding was folded into this file's
content from the start, and this plan's own manual test confirms it
worked on the first try here — the agent asked instead of searching.

Honest limitation, stated in the log itself: the test agent is
Claude-based, not literally Codex/OpenCode/Cursor — it verifies the
AGENTS.md mechanism generically (a markdown file parsed as ambient
context, which every one of those tools does the same way), not those
tools' own specific harness behavior.

## Not this adapter's job

- Claude Code's `SKILL.md` format — `adapters/claude-code/` (017).
- `.cursor/rules/*.mdc` glob-scoped activation — deferred; Cursor
  already reads this `AGENTS.md` directly in Agent mode.
- Antigravity/Grok Build (019) — separate plan, unverified conventions.
- CI-pipeline enforcement — `policy/engine.py` (003) /
  `action/integrations.py` (016), not an interactive-review adapter's
  job.

## Cross-platform

`test_agents_md_structure.py`'s only file reads specify
`encoding="utf-8"` explicitly. Verify with (from inside this
directory):
```
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_agents_md_structure -v
```
(macOS/Linux; see the top-level `security-skill/README.md`.)
