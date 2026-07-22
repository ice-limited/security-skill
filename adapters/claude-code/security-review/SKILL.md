---
name: security-review
description: Run security-skill's detectors when the user asks for a security review, a vulnerability/security audit, "check this Dockerfile/Terraform/pipeline/API spec for security issues", or similar during a PR/code review or ad hoc repo review. Invokes real static-analysis detectors (secrets, injection/SSRF, authn/authz, dependency CVEs, Docker, Kubernetes, IaC, API, supply-chain, CI/CD pipeline) and reports their real structured findings — never a substitute for actually running them.
allowed-tools: Bash, Read, Grep, Glob
---

# Security Review

Routes a security-review request to the right `security-skill/` detector(s)
and reports their real output. This file stays short on purpose — the
per-sub-skill detail lives in `reference/*.md`, one file per sub-skill,
opened only when actually needed (see
`plans/017-claude-code-adapter.md` and
`meetings/2026-07-23-1200-plan-017-kickoff.md` in the
security-skill-workspace repo for why).

## Hard rule: always invoke the real detector, never substitute your own judgment

This skill exists specifically so findings carry
security-skill's own Problem/Impact/Recommendation/Reference/severity/
confidence structure (`schema/finding.schema.json`), the same way a
human security reviewer would cite OWASP/CWE/NIST SSDF — not generic
LLM commentary. **If a detector's prerequisite tool isn't installed,
say so and tell the user how to install it (each wrapper's own error
message already names the exact command — relay it verbatim). Do not
fall back to reviewing the code yourself as if that were equivalent.**
An honest "I can't run this check, here's what's missing" is correct
behavior; a plausible-sounding review that never actually ran the
detector is not.

## Locating `security-skill/`

This file lives at `security-skill/adapters/claude-code/security-review/SKILL.md`.
Every command below is written relative to `security-skill/`'s own
repo root. If this skill directory was **symlinked** into a target
repo's `.claude/skills/`, that relative path still resolves through the
symlink to the real checkout. If it was **copied** instead (also a
supported install method — see the plan), those relative paths won't
resolve.

**When a detector command fails with "no such file or directory" for
its own script path, stop and ask the user where their
`security-skill/` checkout lives — do not go looking for one yourself**
(e.g. searching the filesystem for a directory that happens to match).
Found-and-verified during this plan's own manual test: an agent that
searches on its own initiative may find and use the *wrong* checkout
(a different clone, a different branch/version, or — in a shared
environment — one belonging to a different project entirely), silently
running detector code the user never pointed it at. Asking costs one
turn; guessing risks running the wrong code without anyone noticing.

## Step 1 — identify what's being reviewed

Look at the files actually in scope (the diff, the files the user
named, or a full-repo scan if asked for one). Match extensions/paths to
`finding.schema.json`'s `artifactType` values:

| You see... | artifactType | Sub-skill(s) | Reference doc |
|---|---|---|---|
| `Dockerfile*` | dockerfile | Docker | `reference/docker.md` |
| `*.tf`, `*.tf.json` | terraform | IaC | `reference/iac.md` |
| CloudFormation templates | cloudformation | IaC | `reference/iac.md` |
| Ansible playbooks | ansible | IaC | `reference/iac.md` |
| `*.yaml`/`*.yml` under `k8s/`, `manifests/`, Helm charts | kubernetes-yaml/helm | Kubernetes | `reference/kubernetes.md` |
| `.github/workflows/*.yml` | github-actions | CI/CD Pipeline, Supply Chain | `reference/cicd-pipeline.md`, `reference/supply-chain.md` |
| `.gitlab-ci.yml` | gitlab-ci | CI/CD Pipeline | `reference/cicd-pipeline.md` |
| `Jenkinsfile` | jenkinsfile | CI/CD Pipeline | `reference/cicd-pipeline.md` |
| package manifests/lockfiles | package-lock | Dependency | `reference/dependency.md` |
| OpenAPI/other API specs | api-spec | API | `reference/api.md` |
| Application source code | source-code | Code Review, Auth, API (open redirect) | `reference/code-review.md`, `reference/auth.md` |
| Any file, any type | (all of the above) | Secret | `reference/secret.md` — always run this one; secrets can leak into any file type |

A single review often spans several rows — run every detector that
applies, not just the first match.

## Step 2 — for each matching sub-skill

1. Open that sub-skill's `reference/{sub-skill}.md`.
2. Run the exact command it documents, via your Bash tool, against the
   real file(s)/path in scope.
3. If it exits non-zero because a prerequisite tool is missing, relay
   that error to the user (see the hard rule above) and skip to the
   next applicable sub-skill rather than stopping the whole review.
4. Otherwise, parse the JSON array of `Finding` objects it printed to
   stdout, and report each one's `title`, `severity`, `confidence`,
   `problem`, `impact`, `recommendation`, and `references` — in your own
   words is fine for framing, but every fact must come from the
   finding's own fields, not invented.

## Step 3 — summarize

If multiple detectors ran, group findings by severity
(Critical/High/Medium/Low/Info) across all of them before presenting —
don't just concatenate per-detector output. Mention any detector you
skipped due to a missing prerequisite, and what installing it requires.

## Not this skill's job

- CI-pipeline enforcement (merge blocking, tickets, notifications) —
  that's `policy/engine.py` (003) and `action/integrations.py` (016),
  which assume a `ScanReport` envelope + policy config already exist;
  wiring those into an actual CI step is a separate, not-yet-scoped
  plan, not this interactive-session skill.
- Producing a full `ScanReport` envelope (`schemaVersion`/`scanId`/etc.)
  or a rendered Markdown/HTML report via `schema/render_markdown.py` —
  useful for a PR-comment-style artifact, but not required for an
  interactive review; assembling one is a reasonable follow-up if the
  user asks for a shareable report, not this skill's default behavior.
