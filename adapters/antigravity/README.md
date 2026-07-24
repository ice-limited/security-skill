# adapters/antigravity/

The Antigravity adapter (plan 019) — **no new content authored**. Real
research at this plan's kickoff (see `plans/019-antigravity-grok-build-adapter.md`
and `meetings/2026-07-24-1100-plan-019-kickoff.md` in the
security-skill-workspace repo) found, via Antigravity's own first-party
docs (`antigravity.google/docs/ide/skills`), that its Skill format is
structurally identical to Claude Code's: a directory containing
`SKILL.md` with YAML frontmatter (`name`, `description`) and the same
progressive-disclosure behavior — just discovered from a different
location, `.agents/skills/<name>/` (or legacy `.agent/skills/`) instead
of `.claude/skills/<name>/`.

## `skills/security-review` — a symlink, not a copy

`skills/security-review` is a **symlink** to
`../../claude-code/security-review` (017's own content), not a
duplicate. Decided at kickoff (ก้อง's recommendation): duplicating the
same instructions in two places would let a future fix (like the one
017's own manual test found and applied) silently drift out of sync if
it only lands in one copy. One real source of content, two discovery
paths.

## `AGENTS.md` coverage

Antigravity also reads `AGENTS.md` at the project root at session
start — already covered by `adapters/agents-md/AGENTS.md` (018) with no
changes needed here.

## Distribution

Copy or symlink `skills/security-review/` into your own repo's
`.agents/skills/security-review/` (or the legacy `.agent/skills/` path)
— same "symlink over copy" recommendation as 017's own distribution
note, for the same reason.

## Verification status — honest gap, not silently skipped

**Antigravity itself could not be verified in this development
environment** — it's a GUI-based agentic IDE with no CLI entry point
found here (`antigravity` is not on `PATH`), unlike Grok Build (see
`../grok-build/`), which has a real, scriptable CLI this plan could
actually run against. The claim that Antigravity's Skill format
matches Claude Code's closely enough for the symlinked content to work
unmodified rests on Antigravity's own documentation, not a first-hand
test — per มิ้นท์'s point at kickoff, this gap is documented here
explicitly rather than glossed over. A real verification (installing
Antigravity, dropping this symlinked skill into a scratch repo's
`.agents/skills/`, and confirming it triggers and invokes a real
detector) is a reasonable follow-up whenever Antigravity is actually
available to test against — not done in this pass.

## Not this adapter's job

- Claude Code's own `SKILL.md` content — authored in
  `adapters/claude-code/` (017); this directory only symlinks to it.
- `AGENTS.md` content — authored in `adapters/agents-md/` (018).
- Grok Build — see `../grok-build/` (also no new content, but verified
  for real via `grok inspect` in this same environment).
