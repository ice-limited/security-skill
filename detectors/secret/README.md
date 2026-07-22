# detectors/secret/

Pattern + entropy-based hardcoded-secret detection. First Phase 1
sub-skill, first real detector in `security-skill/` — see
`plans/006-secret-detection-skill.md` and
`meetings/2026-07-22-1359-plan-006-kickoff.md` in the
security-skill-workspace repo for design rationale. Also the first
2-level-deep directory (`detectors/secret/`), which is what plan 005's
`common/` path-discovery fix was written for.

## What this detects

8 rules, patterns adapted from [gitleaks](https://github.com/gitleaks/gitleaks)
(`config/gitleaks.toml`, MIT License, Copyright (c) 2019 Zachary Rice —
verified MIT before adapting, trufflehog was considered and rejected as
a source for being AGPL-3.0):

| ruleId | Confidence | Source |
|---|---|---|
| `secret.aws-access-key` | 95 | gitleaks `aws-access-token` |
| `secret.github-pat` | 95 | gitleaks `github-pat` |
| `secret.gitlab-pat` | 95 | gitleaks `gitlab-pat` |
| `secret.jwt` | 80 | gitleaks `jwt` |
| `secret.private-key` | 98 | gitleaks `private-key` |
| `secret.gcp-api-key` | 95 | gitleaks `gcp-api-key` |
| `secret.azure-ad-client-secret` | 85 | gitleaks `azure-ad-client-secret` |
| `secret.generic-api-key` | 60 | gitleaks `generic-api-key` (context keyword + entropy check) |

Full rule definitions (patterns, problem/impact/recommendation text,
standards references) are in `rules.py`.

## Design decisions from the kickoff

- **Artifact-type-agnostic.** Scans raw text/lines uniformly — a secret
  looks the same in a `.env`, a Dockerfile `ENV`, or a Kubernetes
  manifest. `artifactType` on each finding comes from the caller
  (`scan_file(path, artifact_type=...)`), not inferred here.
- **Severity is always `Critical`**, independent of confidence — these
  are orthogonal per `finding.schema.json` (severity = how bad if real,
  confidence = how sure we are).
- **Bare high-entropy strings with no contextual keyword are not
  flagged** — highest false-positive-risk case, deferred until plan
  020's fixture corpus can measure the false-positive rate rather than
  guessing at it.
- **Byte offsets are true byte offsets**, computed by encoding the
  prefix and measuring it — not `str` character positions, which
  diverge from byte positions once multi-byte UTF-8 content appears
  before a match.
- **`findingId` includes byte offsets**, not just line range — so two
  matches of the *same rule* on the same line (e.g. two different AWS
  keys side by side) get distinct IDs. Getting this wrong was caught by
  mutation-testing the original (weaker) test, which only checked two
  *different* rules on the same line — never actually ambiguous, since
  `ruleId` alone already distinguished them.
- **A specific rule's match suppresses an overlapping
  `secret.generic-api-key` match on the same underlying secret.** Found
  during a second testing pass: a high-entropy AWS-key-shaped value
  assigned to `aws_key = "..."` cleared the generic rule's entropy gate
  too, producing two findings for one secret. `scan_text()` drops a
  generic-rule finding whenever its byte range overlaps a more specific
  rule's finding in the same scan — intra-detector overlap, distinct
  from plan 004's deliberately-deferred cross-detector dedup.

## Usage

```python
from scanner import scan_text, scan_file

findings = scan_text(file_content, "config.env")
findings = scan_file(Path("config.env"), artifact_type="config")
```

```
python3 scanner.py path/to/file [--artifact-type dockerfile]
```

## Not this detector's job

- File selection/exclusion (which paths get scanned) — orchestration
  concern, not the detector's (CONTEXT.md §5's changed-files/diff
  input).
- Revocation/rotation of found secrets — Action layer (015/016).
- Confidence calibration — deferred to plan 004's plug-in point, once
  there's real true/false-positive data to calibrate against.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v`
(macOS/Linux; see the top-level `security-skill/README.md`).
