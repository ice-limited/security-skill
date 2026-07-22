# Code Review — reference

SQLi, XSS, SSRF, Command Injection (injection/taint-tracking classes —
authn/authz is a separate sub-skill, see `reference/auth.md`).

## Command

```
python3 detectors/code-review/scanner.py path/to/file_or_dir [--config p/owasp-top-ten] [--artifact-type source-code]
```

## Prerequisite

Requires the real `semgrep` CLI on `PATH` (`pip install semgrep`). If
missing, the command fails with a clear error naming that exact install
command — relay it verbatim to the user per `SKILL.md`'s hard rule; do
not review the code yourself as a substitute.

## Output

A JSON array of `Finding` objects on stdout (`ruleId` prefix
`code-review.*`). Report each one per `SKILL.md`'s Step 2.
