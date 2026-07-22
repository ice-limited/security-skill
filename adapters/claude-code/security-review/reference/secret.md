# Secret — reference

**Always run this one**, regardless of what other artifact types are in
scope — hardcoded secrets can leak into any file.

## Command

```
python3 detectors/secret/scanner.py path/to/file [--artifact-type dockerfile|source-code|...]
```

Run once per file in scope (or loop over the changed files in a diff).
No external tool required — pure Python, pattern + entropy based.

## What it catches

8 rules (`secret.aws-access-key`, `secret.github-pat`,
`secret.gitlab-pat`, `secret.jwt`, `secret.private-key`,
`secret.gcp-api-key`, `secret.azure-ad-client-secret`,
`secret.generic-api-key`) — see `detectors/secret/README.md` for full
detail.

## Output

A JSON array of `Finding` objects on stdout. Report each one per
`SKILL.md`'s Step 2 — never redact/paraphrase away the exact
`location.file`/`startLine`, since that's what the user needs to find
and fix it.

## No prerequisite tool

This detector has no missing-tool failure mode to handle — it never
skips silently.
