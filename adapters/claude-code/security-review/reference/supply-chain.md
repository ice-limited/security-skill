# Supply Chain — reference

SBOM presence/validity, dependency provenance, container image signing,
SLSA, committed binary artifacts, missing SAST tooling.

## Commands

Run all three against the repo root (or the relevant subpath) — they
check different things:

```
python3 detectors/supply-chain/scanner.py .github/workflows/    # GitHub Actions config-presence checks
python3 detectors/supply-chain/sbom_scanner.py .                # validates SBOM files against real CycloneDX/SPDX JSON Schemas
python3 detectors/supply-chain/scorecard_wrapper.py .           # OpenSSF Scorecard, curated to Binary-Artifacts/SAST checks
```

## Prerequisite

`scorecard_wrapper.py` requires the real `scorecard` CLI on `PATH`
(`brew install scorecard`). The other two are pure Python, no external
tool. If `scorecard` is missing, relay the error verbatim per
`SKILL.md`'s hard rule and still run the other two.

## Output

Each prints a JSON array of `Finding` objects on stdout (`ruleId` prefix
`supply-chain.*`). Several findings here cite NIST-SSDF practice IDs
instead of a CWE (no CWE fits "missing SBOM/signing/provenance") —
report the reference exactly as given, don't force a CWE onto it.
