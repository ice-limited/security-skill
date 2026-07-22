# knowledge/

Vendored lookup tables for the 8 standards in `finding.schema.json`'s
`references[].standard` enum: `OWASP-Top10`, `OWASP-ASVS`,
`OWASP-API-Top10`, `CWE`, `CAPEC`, `MITRE-ATTACK`, `NIST-SSDF`,
`CERT-Secure-Coding`.

**What this is:** a lightweight `id -> {title, url}` lookup per standard
(plus an `authoritative-only` `relatedCwe` crosswalk where the standards
body itself publishes one — currently OWASP Top 10 → CWE and CAPEC → CWE).
**What this isn't:** a mirror of the full standards' guidance text — see
`plans/002-knowledge-base-standards-mapping.md` and
`meetings/2026-07-22-1116-plan-002-kickoff.md` in the
security-skill-workspace repo for why.

## Files

| File | Standard | Notes |
|---|---|---|
| `cwe.json` | CWE | URL derived from ID (`cwe.mitre.org/data/definitions/{n}.html`) |
| `capec.json` | CAPEC | URL derived from ID; `relatedCwe` = MITRE's own documented mapping |
| `owasp-top10.json` | OWASP-Top10 | **2025 edition** (current as of 2026-07-22 — superseded 2021) |
| `owasp-api-top10.json` | OWASP-API-Top10 | 2023 edition (current) |
| `owasp-asvs.json` | OWASP-ASVS | **5.0.0** (current as of 2026-07-22 — superseded 4.0.3); chapters V1-V11 confirmed, may be incomplete, see file's `_note` |
| `mitre-attack.json` | MITRE-ATTACK | Minimal starter set (2 techniques), grows on demand |
| `nist-ssdf.json` | NIST-SSDF | Top-level practice groups only (PO/PS/PW/RV) |
| `cert-secure-coding.json` | CERT-Secure-Coding | Empty — per-language rules, seeded once a detector language is chosen |

Every ID and URL in these files that isn't derived from a template was
verified against the live standard's own site while implementing this
plan, not recalled from memory — OWASP in particular had shipped new
editions (Top 10:2025, ASVS 5.0.0) that training-data recall would have
gotten wrong.

## Usage

```python
import standards

standards.exists("CWE", "CWE-89")      # True
standards.title("CWE", "CWE-89")       # "Improper Neutralization of ..."
standards.url("CWE", "CWE-89")         # "https://cwe.mitre.org/..."
```

```
python3 validate_references.py path/to/scan-report.json
```

Checks every `references[]` entry in a ScanReport (schema/scan-report.schema.json)
against this knowledge base — a *semantic* check (does this ID actually
exist?), distinct from `schema/validate.py`'s structural JSON Schema
check (is the shape right?).

```
python3 check_freshness.py
GITHUB_TOKEN=ghp_... python3 check_freshness.py   # higher rate limit
```

Checks whether `owasp-top10.json`, `owasp-asvs.json`, and
`owasp-api-top10.json`'s recorded `_edition` still matches each
standard's current edition on GitHub (the mechanism that would have
caught the stale-2021-edition mistake plan 002 almost shipped). It
**flags** drift for manual re-verification — it does not rewrite these
files itself. See `plans/021-knowledge-base-freshness-checker.md` in the
security-skill-workspace repo. On-demand only for now; not wired into
CI/scheduling yet.

## Growing this data

Add entries as sub-skill detectors (plans 006–014) need to cite them —
don't pre-populate speculatively (e.g. don't seed all 900+ CWEs). When
adding a `relatedCwe` crosswalk entry, verify it against the standard's
own published page first; don't invent a mapping (see plan 002's
"authoritative-only" decision).
