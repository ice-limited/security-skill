# Kubernetes — reference

`hostNetwork`, `privileged`, `hostPID`, `hostPath`, root user, `:latest`
tag, missing resource limits, missing `readOnlyRootFilesystem`, +
related. Covers both plain Kubernetes YAML manifests and Helm charts.

## Command

```
python3 detectors/kubernetes/scanner.py path/to/manifests-or-chart
```

## Prerequisite

Requires the real `trivy` CLI on `PATH` (`brew install trivy`, or a
prebuilt binary on Windows/Linux). Helm-chart-specific checks
additionally require the real `helm` CLI on `PATH`. If either is
missing, relay the error verbatim per `SKILL.md`'s hard rule — plain
YAML manifests can still be checked even if `helm` specifically is
absent.

## Output

A JSON array of `Finding` objects on stdout (`ruleId` prefix
`kubernetes.*`). Report each one per `SKILL.md`'s Step 2.
