# CI/CD Pipeline — reference

GitHub Actions, GitLab CI, Jenkinsfile: script injection, unpinned
references, secrets in logs, excessive permissions, + related. Like
Auth, this is **hybrid** — a deterministic half plus a playbook.

## Mechanism 1 — deterministic (`scanner.py`)

```
python3 detectors/cicd/scanner.py path/to/repo
```

Wraps Checkov (6 curated rule_ids across GitHub Actions + GitLab CI —
chosen over the more deeply-covering but GitHub-Actions-only `zizmor`,
a deliberate consistency trade-off with `detectors/iac/`, which also
wraps Checkov via the same `common/checkov_wrapper.py`).

### Prerequisite

Requires the real `checkov` CLI on `PATH` (`pip install checkov`). If
missing, relay the error verbatim per `SKILL.md`'s hard rule, then still
run Mechanism 2 below (it doesn't depend on checkov).

## Mechanism 2 — the playbook (`playbook.py`)

Checkov has **zero deterministic coverage for Jenkinsfile** and doesn't
reach everything in GitHub Actions/GitLab CI either. Same pattern as
`reference/auth.md`'s playbook: this is a checklist *you* apply
directly while reading the pipeline config, not a script you parse.

```
python3 detectors/cicd/playbook.py --format github-actions   # or gitlab-ci / jenkinsfile
```

Read the printed checklist, inspect the pipeline config against each
item, and construct any finding yourself in the same `Finding` shape
every other detector produces — see `reference/auth.md`'s playbook
section for the exact reasoning on why this still counts as "the real
detector," not a substitute for one.

## Output (Mechanism 1)

A JSON array of `Finding` objects on stdout (`ruleId` prefix
`cicd-pipeline.*`). Report each one per `SKILL.md`'s Step 2.
