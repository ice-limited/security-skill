# detectors/supply-chain/

Supply chain security review — **three independent mechanisms**, none
of them Checkov-based (unlike 011/013), each covering a distinct slice
of CONTEXT.md §7's Supply Chain sub-skill scope. See
`plans/014-supply-chain-skill.md` and
`meetings/2026-07-22-2350-plan-014-kickoff.md` in the
security-skill-workspace repo for design rationale.

| Module | Mechanism | Covers |
|---|---|---|
| `ci_config.py` + `scanner.py` | hand-written GitHub Actions workflow parsing (`ruamel.yaml`) | Missing image signing, missing SBOM generation, missing SLSA provenance |
| `sbom_validate.py` + `sbom_scanner.py` | real JSON-Schema validation against vendored CycloneDX/SPDX schemas | SBOM content validity |
| `scorecard_wrapper.py` | OpenSSF Scorecard (`--local`, curated to 2 checks) | Committed binary artifacts, missing SAST tooling |

**Static/config-presence only, by design** — confirmed at this plan's
kickoff after verifying `cosign verify` (live registry verification)
genuinely works in this environment: every other detector in this
project is static/local-file analysis, and a live network call per
scan would make this the only non-deterministic-across-runs check in
the whole skill. Nothing here ever calls out to a container registry,
Rekor, or the GitHub API.

## Why not Checkov's `CKV_GHA_5`/`CKV_GHA_6`?

The kickoff's original design planned to reuse Checkov's own Cosign
checks (already found, deferred from 013). **Verified at implementation
that both are non-functional real bugs**, not a narrow gap: their
`scan_conf()` loop iterates the parsed `jobs:` dict and unconditionally
returns `PASSED` the moment it encounters Checkov's own
`__startline__`/`__endline__` metadata keys — which every real parsed
`jobs:` mapping has — discarding whatever "build step found, no
signing step after it" state the loop had already accumulated.
Confirmed via three distinct real fixtures (unsigned single-job,
signed single-job, unsigned two-job) run through
`checkov.github_actions.runner.Runner` directly: **these checks never
return `FAILED`, regardless of input.** `ci_config.py`/`scanner.py`
replace them with hand-written checks instead, mirroring 009's own
precedent for gaps no existing tool covers.

## `ci_config.py` + `scanner.py` — CI config-presence checks

Per job: does it build a container image (matches the same
build-action/build-command patterns Checkov's own broken checks used,
reused here as plain constants, not an import from checkov), and —
among steps *after* the build step — is there a signing step
(`cosign sign`) and/or an SBOM-generation step (`cosign attest`,
`syft`, `cyclonedx`, `anchore/sbom-action`)? Workflow-wide (not
per-job): does any job reference the official SLSA provenance
generator (`slsa-framework/slsa-github-generator`)?

**Real bug found and fixed during this plan's own fixture-building,
not assumed**: an earlier version of `has_slsa_provenance_generator()`
only checked `uses:` inside a job's `steps:` list. The SLSA generator
is actually invoked as a **job-level reusable-workflow call**
(`jobs.<id>.uses: slsa-framework/...@ref`, no `steps:` for that job at
all) — the far more common real pattern for this specific generator.
Fixed by checking both shapes; caught by building a realistic
"fully clean" fixture and finding it still (wrongly) flagged, not by
inspection alone.

No CWE cleanly covers any of these three checks (see `rules.py`'s own
docstring) — all three cite **NIST-SSDF** only: PS.2/PS.2.1 (signing),
PS.3.2 (SBOM/provenance), fetched directly from NIST SSDF (SP 800-218)
sources at implementation.

## `sbom_validate.py` + `sbom_scanner.py` — SBOM validity

Detects a file's SBOM format from its own self-declared fields
(`bomFormat: CycloneDX` or a `spdxVersion` key — never guessed from the
filename), then validates it against the real, vendored CycloneDX
1.6 / SPDX 2.3 JSON Schema (see `schemas/README.md` for exact source/
license). Uses `jsonschema.validators.validator_for(schema)` rather
than `common/schema_validation.py`'s hardcoded `Draft202012Validator` —
both vendored schemas are JSON Schema **draft-07**, and forcing a
2020-12 validator onto a draft-07 schema would be incorrect, not just
inconsistent. This is presence-of-a-*valid* SBOM; whether the pipeline
generates one *at all* is `scanner.py`'s job
(`supply-chain.missing-sbom-generation`) — a repo with no SBOM file
produces zero findings here, that's not a validity problem.

## `scorecard_wrapper.py` — OpenSSF Scorecard, curated to 2 checks

`Binary-Artifacts` (committed executables) and `SAST` (whether a SAST
tool is configured in CI) — both verified at kickoff to run in
`--local` mode with no GitHub token and no overlap with any existing
sub-skill. Excluded: `Pinned-Dependencies` (overlaps 009's
`docker.unpinned-base-image` and 013's own unpinned-reference playbook
item — verified by running it directly), `Dangerous-Workflow`/
`Token-Permissions` (overlap 013's own scope), `Signed-Releases`
(verified **incompatible** with `--local` mode outright — fails with
`"Unsupported RequestType"`, since it needs the GitHub Releases API).

**Real, documented limitation, not silently papered over**: Scorecard's
`--local` mode walks the actual filesystem, not just git-tracked
content (verified it still reports `.gitignore`d `__pycache__/*.pyc`
files as "binaries," and `--file-mode git` doesn't change this for
local scans), and **crashes outright** scanning a directory containing
certain symlinks (verified: a macOS Python virtualenv's `.venv/bin/`
symlink triggers an internal `"path escapes from parent"` error — a
real Scorecard bug, reproduced with a minimal synthetic symlink
fixture, not just observed once). `run_scorecard()` surfaces this as an
actionable `ScannerError` rather than silently returning no findings —
point this wrapper at a real target checkout, not a directory
containing a Python virtualenv or similar symlink-heavy tooling
directory.

## Usage

```python
import scanner          # CI config-presence (signing/SBOM-gen/SLSA)
import sbom_scanner      # SBOM content validity
import scorecard_wrapper # Binary-Artifacts / SAST

findings = scanner.scan_paths([".github/workflows/"])
findings += sbom_scanner.scan_paths(["."])
findings += scorecard_wrapper.scan_paths(["."])  # exclude .venv/node_modules-equivalents from the target path
```

```
python3 scanner.py .github/workflows/
python3 sbom_scanner.py .
python3 scorecard_wrapper.py .
```

## Not this module's job

- Live `cosign verify`/`slsa-verifier verify-image` against a real
  registry — confirmed technically possible at kickoff, decided
  against for consistency with every other detector.
- SBOM/signature *generation* — an Action-layer capability (015), not
  detection.
- GitLab CI / Jenkinsfile equivalents of the CI-config checks — this
  plan's kickoff scoped to GitHub Actions only for the Cosign/SLSA/SBOM
  config-presence checks (013 already covers GitLab CI/Jenkinsfile for
  its own, different scope); a future scope-expansion candidate, not
  v1.
- Measuring whether these checks catch real supply-chain compromises in
  practice — plan 020's job.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with (from inside this directory):
```
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_sbom_scanner -v
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scorecard_wrapper -v
```
(macOS/Linux; see the top-level `security-skill/README.md`.)
