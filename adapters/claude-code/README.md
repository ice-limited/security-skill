# adapters/claude-code/

The Claude Code adapter (plan 017) — the first of this project's thin,
per-tool adapters (see `CONTEXT.md` §2: core content lives once in
`security-skill/`, adapters are thin wiring per tool). See
`plans/017-claude-code-adapter.md` and
`meetings/2026-07-23-1200-plan-017-kickoff.md` in the
security-skill-workspace repo for design rationale.

## `security-review/` — the skill itself

A single router Claude Code Skill, not one skill per sub-skill —
decided at kickoff, using Claude Code's real progressive-disclosure
mechanism (a `SKILL.md` that markdown-links to sibling reference files,
loaded only when Claude actually opens them):

- `SKILL.md` — the router: identifies which artifact type(s) are in
  scope, maps them to the matching sub-skill(s), and hard-requires
  invoking the real detector (never substituting general LLM judgment).
- `reference/{sub-skill}.md` — one per `finding.schema.json` `subSkill`
  enum value (10 files), each documenting that sub-skill's exact
  detector command(s), prerequisite tool(s), and how to handle a
  missing prerequisite.
- `MANUAL_TEST_LOG.md` — a real, human-observed Claude Code session
  run against a scratch repo, since "did Claude decide to invoke this
  skill" isn't provable by a unit test. Found and fixed one real gap in
  `SKILL.md`'s wording as a direct result (see the log).

## Distribution: in-repo `.claude/skills/` only (confirmed at kickoff)

No Claude Code Plugin/marketplace packaging — that would be a
public-facing action needing its own explicit go-ahead, not folded into
this plan. A user wanting this skill in their own repo copies or
**symlinks** `security-review/` into that repo's `.claude/skills/`.

**Symlink, not copy, is the practical recommendation** — every command
in `SKILL.md`/`reference/*.md` is written relative to this
`security-skill/` repo root. A symlinked skill directory still resolves
those relative paths through to the real checkout; a copied one won't,
and `SKILL.md` explicitly hard-requires *asking the user* where their
checkout lives in that case, rather than autonomously searching the
filesystem for one (a real failure mode found during this plan's own
manual test, not a hypothetical).

## `test_skill_structure.py` — what's actually automatable

Whether Claude decides to invoke this skill is not something a unit
test can prove (that's `MANUAL_TEST_LOG.md`'s job). What *is*
automatable, and what this test suite checks: `SKILL.md`'s frontmatter
parses and has the fields Claude Code reads (`name`, `description`),
the description stays under Anthropic's documented 1,536-character
description+`when_to_use` cap, `SKILL.md`'s body stays within the
~500-line guidance, and every `finding.schema.json` `subSkill` enum
value has a matching, non-trivial `reference/*.md` file (no silent
coverage gaps).

```
python3 -m unittest test_skill_structure -v
```

## Not this adapter's job

- The CI-pipeline invocation path (wiring detectors + 016's gate into
  an actual GitHub Actions/GitLab CI step) — a separate, not-yet-scoped
  future plan, per ก้อง at kickoff.
- The AGENTS.md-based adapter (018) or Antigravity/Grok Build (019) —
  separate plans.
- Claude Code Plugin/marketplace packaging — confirmed out of scope by
  the user at kickoff.

## Cross-platform

`test_skill_structure.py`'s only file reads specify `encoding="utf-8"`
explicitly. Verify with (from inside this directory):
```
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_skill_structure -v
```
(macOS/Linux; see the top-level `security-skill/README.md`.)
