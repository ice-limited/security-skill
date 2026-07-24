# adapters/grok-build/

The Grok Build adapter (plan 019) — **no new content authored, and no
new files distributed from here**. Real research at this plan's
kickoff (see `plans/019-antigravity-grok-build-adapter.md` and
`meetings/2026-07-24-1100-plan-019-kickoff.md` in the
security-skill-workspace repo), confirmed by a **real, first-hand test
in this environment** (`MANUAL_TEST_LOG.md`), found that Grok Build
already reads both of this project's existing adapters natively, with
no wiring needed:

- The `AGENTS.md` family (`AGENTS.md`/`Agents.md`/`AGENT.md`, nested,
  root-to-cwd) — `adapters/agents-md/AGENTS.md` (018) already applies.
- `.claude/skills/` directly — `adapters/claude-code/security-review/`
  (017) already applies, with no symlink or copy needed at all (unlike
  Antigravity, see `../antigravity/`, which needs its own discovery
  path wired).

## Distribution

Nothing to distribute from this directory — a repo that already has
either `AGENTS.md` (018) or `.claude/skills/security-review/` (017) in
place is already covered for Grok Build. This directory exists only to
document that reuse explicitly, so a future reader doesn't assume 019
built separate Grok-specific content and go looking for it.

## Verification — real, not just documentation claims

Unlike Antigravity (no CLI available in this environment, see
`../antigravity/README.md`'s honest gap), the real `grok` CLI (v0.2.106)
is installed here. Ran `grok inspect` against a scratch repo containing
only this project's existing `AGENTS.md` (018) and
`.claude/skills/security-review/` (017) — see `MANUAL_TEST_LOG.md` for
the full output. It correctly listed the project instructions file and
the skill (tagged `project [claude]`), confirming real discovery, not
just a documentation claim. Did not run a full end-to-end prompt
(this environment isn't authenticated with xAI), so detector invocation
itself wasn't re-verified here — 017/018's own manual tests already
proved the *content* correctly instructs an agent to invoke a real
detector; what this test needed to confirm was only whether Grok Build
*discovers* that content the same way, which it does.

## Not this adapter's job

- Authoring `AGENTS.md` content — `adapters/agents-md/` (018).
- Authoring the Claude Code Skill content — `adapters/claude-code/` (017).
- Antigravity — see `../antigravity/` (needs its own `.agents/skills/`
  wiring, unlike this one).
