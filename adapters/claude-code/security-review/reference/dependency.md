# Dependency — reference

CVEs, license issues, deprecated/known-malware packages, from real
lockfiles.

## Command

```
python3 detectors/dependency/scanner.py path/to/project [--artifact-type package-lock] [--data-source native]
```

## Prerequisite

Requires the real `osv-scanner` CLI on `PATH` (`brew install
osv-scanner`, or a prebuilt binary/Scoop/WinGet on Windows). If missing,
relay the error verbatim per `SKILL.md`'s hard rule.

Also needs network access to query the OSV database — if the
environment is offline, the command will fail for that reason instead;
relay that too rather than guessing at known CVEs from memory.

## Output

A JSON array of `Finding` objects on stdout (`ruleId` prefix
`dependency.*`, often `dependency.cve` with the specific CVE ID in
`metadata`). Report each one per `SKILL.md`'s Step 2.
