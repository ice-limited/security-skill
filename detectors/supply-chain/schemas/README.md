# Vendored SBOM schemas

Both files here are the actual, official, published JSON Schemas for
their respective SBOM formats — fetched directly at plan 014's
implementation (2026-07-22), not hand-approximated. Used by
`../sbom_validate.py` to validate a repo's checked-in SBOM file content
for real, against the real spec.

| File | Format/version | Source | License |
|---|---|---|---|
| `cyclonedx-bom-1.6.schema.json` | CycloneDX 1.6 | `raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json` | Apache-2.0 (per the schema's own embedded `$comment`, confirmed against the `CycloneDX/specification` repo's GitHub-reported license) |
| `spdx-2.3.schema.json` | SPDX 2.3 | `raw.githubusercontent.com/spdx/spdx-spec/develop/schemas/spdx-schema-2-3.json` | Community Specification License 1.0, with pre-existing portions under CC-BY-3.0 (per the `spdx-spec` repo's own `LICENSE` file, fetched directly — GitHub's license-detection API returned `NOASSERTION` for this repo, so the actual `LICENSE` file was checked instead of trusting that) |

Both are JSON Schema **draft-07** (`"$schema": "http://json-schema.org/draft-07/schema#"`)
— `sbom_validate.py` uses `jsonschema.validators.validator_for(schema)`
to pick the matching validator class automatically, rather than
`common/schema_validation.py`'s hardcoded `Draft202012Validator` (which
is correct for this project's own 2020-12 schemas, but not for these
external draft-07 ones).

Not automatically kept in sync with upstream — re-fetch and re-vendor
if a newer CycloneDX/SPDX version is needed. No freshness-check
automation exists for these yet (unlike `knowledge/check_freshness.py`'s
GitHub-API-based freshness check for OWASP/CWE/etc. standards) — a
candidate for a future plan if staleness becomes a real problem.
