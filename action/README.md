# action/

Action Layer — turns a decided-upon `Finding` (`schema/finding.schema.json`)
into a `Remediation` (`schema/remediation.schema.json`): a safety-tier
assignment, an actionable recommendation, and — only where a genuinely
mechanical transformation exists for that ruleId — a computed patch,
an impact-of-the-fix narrative, and pull-request draft content. See
`plans/015-action-layer-recommendations-autofix.md` and
`meetings/2026-07-23-1000-plan-015-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Pure data generator — no exception to this project's own shape

Every prior plan (001–014) is pure analysis with zero side effects.
015 stays that way: **this module never writes to the target repo's
filesystem, never runs `git`/`gh`, and never calls any external API.**
`patch`/`pullRequestDraft` are data describing a proposed change — the
invoking agent applies a patch itself, and plan 016 is the one that
actually calls a GitHub/GitLab API to open a PR from this module's
`pullRequestDraft` content.

## `remediation.py` — the core builder

`build_remediation(finding, file_content=None, tiers=None)` looks up
the finding's safety tier (`safety_tier_for()`, backed by
`safety_tiers.json`) and, for `secret.*` findings only, generates a
real redaction patch via `generate_secret_redaction_patch()`.

**v1 real-patch scope: `secret.*` (006) only.** One generic
transformation — replace the finding's own matched byte span
(`location.startByte`/`endByte`, already precise since plan 001 built
byte-range addressing in from day one specifically for this) with a
fixed placeholder (`REDACTED_SECRET`) — is mechanically safe across
every secret ruleId. Every other finding gets a safety tier and
recommendation with **no** `patch` field: CONTEXT.md §10.1's own IAM
worked example mentions "generate a Terraform patch" even for its
review-required tier, but computing a *correct* narrower IAM policy
requires knowing what the application actually needs, which this
project's static-analysis-only detectors have no way to determine —
fabricating a patch that looks plausible but was never verified is
worse than an honest recommendation-only remediation (วิน's concern at
kickoff). Extending real patch generation to another sub-skill is a
ruleId-by-ruleId judgment call for a future plan, not assumed here.

## Real bug found and fixed in 006 (Secret Detection) during this plan's implementation

**Not a bug in `action/` itself** — found because 015 is the first
consumer that actually needs byte-perfect precision matching the exact
secret *value*, not just "a span somewhere near it." Two of 006's own
rules (`generic-api-key`, `azure-ad-client-secret`) capture the secret
in a regex group narrower than the whole match (the variable name +
`=` aren't part of the captured group). `detectors/secret/scanner.py`
previously computed `location.startByte`/`endByte` from the *whole
match's* span, not the captured group's — silently over-wide by
everything before the value. A redaction patch built from that span
produced broken output (e.g. `AWS_ACCESS_KEY = "AKIA...` — the entire
assignment redacted, dangling closing quote left over). Fixed at the
source in `detectors/secret/scanner.py` (prefer the capture group's own
span when one exists, mirroring the logic already used to extract the
*value* for the entropy check), with two new regression tests in
006's own `test_scanner.py`, mutation-tested to confirm they actually
catch the regression.

## `safety_tiers.json`/`safety_tiers.schema.json` — the tier table

`ruleOverrides` covers every ruleId that exists in this repo, as of
this plan's implementation, for sub-skills with a fixed rule catalog
(006/009–014/023). `subSkillDefaults` is the fallback for ruleIds
generated dynamically (007's Semgrep-check-id-derived ruleIds, most of
008's CVE-derived ones) — no fixed, exhaustive table is possible for
those the way it is for a static catalog.
`test_remediation.py`'s `ConsistencyTests` cross-checks this for real:
it dynamically loads every sub-skill's own rule catalog (via
`importlib`, not a hardcoded copy) and confirms every real ruleId
resolves to a tier — not just assumed covered by the fallback.

Default assignment, decided at kickoff and applied per-ruleId
(documented in the file itself, not inferred ad hoc): `secret.*` →
`auto-apply`; everything else → `review-required` by default;
`recommend-only` reserved for findings whose recommendation is
inherently org-specific (e.g. `supply-chain.missing-sast-tool` — this
skill can't know which SAST tool an org will pick;
`api.jwt-missing-bcp-declaration` — a documentation nudge, not an
actionable fix).

## Usage

```python
import remediation

tiers = remediation.load_safety_tiers()
rem = remediation.build_remediation(finding, file_content=source_text)  # file_content only needed for secret.* findings
errors = validate_remediation(rem)  # schema/validate.py
```

```
python3 remediation.py path/to/finding.json --source-file path/to/scanned_file.py
```

## Not this module's job

- Applying a patch to disk, running `git`, or calling any API —
  confirmed at kickoff, the invoking agent's job.
- Actually opening a pull request from `pullRequestDraft` — plan 016's
  job.
- Sandboxed patch validation (apply + run the target repo's own
  build/lint/test) before tier-1 eligibility — confirmed out of scope
  for v1 at kickoff; no sandbox infrastructure exists anywhere in this
  project yet.
- Real computed patches for sub-skills beyond `secret.*` — a future
  plan's ruleId-by-ruleId work, not promised here.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with (from inside this directory):
```
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_remediation -v
```
(macOS/Linux; see the top-level `security-skill/README.md`.)
