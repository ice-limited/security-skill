# Manual Test Log — Grok Build discovery (plan 019)

Real `grok` CLI (v0.2.106) found installed in this development
environment (`/Users/ice/.grok/bin/grok`) — unlike Antigravity, which
has no CLI here (see `../antigravity/README.md`). Not authenticated
with xAI in this environment, so a full end-to-end prompt/detector
invocation wasn't run — but `grok inspect` (static config discovery,
no LLM call) is real and requires no authentication, and directly
answers this plan's actual open question: **does Grok Build discover
017/018's existing content, not just claim to per its docs.**

## Setup

A scratch git repo (outside both `security-skill-workspace/` and
`security-skill/`) containing only:
- `AGENTS.md` — copied verbatim from `adapters/agents-md/AGENTS.md` (018).
- `.claude/skills/security-review/` — copied verbatim from
  `adapters/claude-code/security-review/` (017).

No Grok-specific files of any kind — the point was to confirm Grok
discovers *this project's existing adapters* unmodified.

## Command and real output

```
$ grok inspect
```

```
  Environment
  └ Version: 0.2.106 [unknown]
  └ CWD: <scratch repo path>
  └ Git root: <scratch repo path>/
  └ Project trusted: yes

  Project Instructions (1)
  └ <scratch repo path>/Agents.md (project, ~1461 tokens)

  ...

  Skills (143)
  └ security-review               project [claude]
  └ check-work                    bundled
  └ code-review                   bundled
  ...
```

(Full output includes this environment's own unrelated personal/bundled
skills — 142 others besides `security-review` — trimmed here to what's
relevant.)

## What this confirms

- **`Project Instructions (1)`** picked up the `AGENTS.md` file
  (displayed as `Agents.md` — a display-casing normalization, same
  file, confirmed by the token count matching its real content) with no
  extra configuration.
- **`Skills (143)`** lists `security-review` tagged `project [claude]`
  — Grok Build genuinely discovered `.claude/skills/security-review/`
  as a real project-level skill, recognizing it came from the
  Claude-style skills convention, exactly as its own docs claim
  ("Grok automatically reads Claude Code ... skills").

## What this does not confirm

- That Grok Build's own agent loop, given a real prompt, actually
  invokes the security detector end-to-end the way 017/018's own
  manual tests confirmed for their respective harnesses. That would
  need real xAI authentication in this environment, which isn't
  present. Not fabricated or assumed here — 017/018 already proved the
  *content itself* correctly instructs an agent to invoke a real
  detector; what was genuinely unverified before this test, and is now
  confirmed, is whether Grok Build *discovers* that content at all.

## Net conclusion

No new content needed for Grok Build. Real, first-hand confirmation
(not just documentation claims) that it discovers both 017's Claude
Code Skill content and 018's `AGENTS.md` content unmodified.
