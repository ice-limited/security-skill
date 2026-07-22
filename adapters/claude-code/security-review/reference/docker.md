# Docker — reference

`FROM latest`, `USER root`, missing `HEALTHCHECK`, `ADD` vs `COPY`,
`curl | bash`, `apt upgrade`, secrets in `ENV`, + related.

## Command

```
python3 detectors/docker/scanner.py path/to/project [--artifact-type dockerfile]
```

## Prerequisite

Requires the real `trivy` CLI on `PATH` (`brew install trivy`, or a
prebuilt binary on Windows/Linux). If missing, relay the error verbatim
per `SKILL.md`'s hard rule.

## Output

A JSON array of `Finding` objects on stdout (`ruleId` prefix
`docker.*`). Report each one per `SKILL.md`'s Step 2.
