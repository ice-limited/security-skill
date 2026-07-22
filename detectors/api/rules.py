"""API spec-lint rule catalog: a curated subset of
`@stoplight/spectral-owasp-ruleset` (MIT, github.com/stoplightio/
spectral-owasp-ruleset), mapped to hand-authored CWE/OWASP API Security
Top 10 (2023) references.

Decided at the plan 012 kickoff (see plans/012-api-skill.md and
meetings/2026-07-22-2200-plan-012-kickoff.md in the
security-skill-workspace repo): the ruleset's own rule codes
(`owasp:apiN:2023-*`) carry only an OWASP API category tag, no CWE —
same situation 009/010/011 found with Trivy/Checkov, requiring
hand-curated references here rather than inheriting them from the tool.

The full ruleset ships 31 rule codes across API1/2/3/4/5/7/8/9:2023.
Curated down to 26 codes / 16 rule_ids for v1 (mirroring 010/011's own
"curate now, expand later" precedent) — excluded, as a judgment call
matching 011's own CKV_AWS_135 precedent (excluding a real check with
no attacker-relevant CIA impact):

- `owasp:api8:2023-define-error-validation` / `-define-error-responses-401`
  / `-define-error-responses-500` — response-schema documentation
  completeness, not an active vulnerability by itself.
- `owasp:api9:2023-inventory-access` / `-inventory-environment` — server
  metadata documentation completeness, same reasoning.

Several rule_ids intentionally group more than one Spectral code where
the underlying weakness is identical and the codes are just variants
(e.g. `-no-additionalProperties` and `-constrained-additionalProperties`
are both "mass assignment via unconstrained schema," just triggered by
different JSON Schema shapes) — mirrors 011's `rule_id -> {check_id}`
grouping precedent, adapted here to `rule_id -> [spectral codes]`.

CWE references verified directly against cwe.mitre.org at
implementation (2026-07-22), not guessed:
- CWE-862 ("Missing Authorization") — reused from existing knowledge
  base entry, fits unprotected read/write operations and un-isolated
  admin endpoints (OWASP API5:2023, Broken Function Level Authorization)
  equally well.
- CWE-915 ("Improperly Controlled Modification of Dynamically-
  Determined Object Attributes") — reused, exact fit for mass
  assignment via permissive `additionalProperties`/`unevaluatedProperties`.
- CWE-400 ("Uncontrolled Resource Consumption") — reused from 010's own
  precedent (missing Kubernetes resource limits) for the identical
  underlying concept applied to API rate-limiting and unbounded
  request/response schemas; OWASP API4:2023 is literally named
  "Unrestricted Resource Consumption."
- CWE-522 ("Insufficiently Protected Credentials"), CWE-598 ("Use of
  HTTP Request With Sensitive Query String"), CWE-345 ("Insufficient
  Verification of Data Authenticity"), CWE-613 ("Insufficient Session
  Expiration"), CWE-942 ("Permissive Cross-domain Security Policy with
  Untrusted Domains"), CWE-319 ("Cleartext Transmission of Sensitive
  Information") — newly added to knowledge/cwe.json for this plan,
  fetched directly from cwe.mitre.org.
- CWE-639 ("Authorization Bypass Through User-Controlled Key") — reused
  as-is; fits predictable/numeric resource IDs enabling IDOR-style
  enumeration.
- CWE-918 ("Server-Side Request Forgery (SSRF)") — reused as-is for
  `concerning-url-parameter`. Same CWE as 007's code-level SSRF scope,
  but a spec-level heuristic (a URL-shaped parameter name) can never
  share a location with a code-level taint-tracking finding (different
  artifact/file entirely), so this is a complementary signal, not a
  duplicate-finding risk like the JWT/mass-assignment overlap with 023
  that this plan's cross-reference half was scoped to avoid.
- CWE-287 ("Improper Authentication") — reused for insecure/outdated
  auth schemes (Negotiate, Digest, etc.), rather than adding a new CWE
  for a narrower fit.

OWASP-API-Top10 pairing uses the category number already embedded in
each Spectral code's own `apiN` prefix — `knowledge/owasp-api-top10.json`
(plan 002) already seeds all 10 categories, so no knowledge-base
addition was needed for these pairings.

Two real Spectral rule-trigger quirks verified directly at
implementation (not assumed from the ruleset's own description text),
both affecting test fixture design:
- `no-additionalProperties`/`constrained-additionalProperties` only
  fire when `additionalProperties` is *explicitly present* (`true`, or
  an unconstrained sub-schema) — omitting the keyword entirely (JSON
  Schema's own default-allow behavior) does **not** trigger either
  rule, confirmed against a minimal isolated fixture. `problem` text
  above is worded to match this real behavior, not the broader
  conceptual risk (which also includes silent omission).
- `no-unevaluatedProperties`/`constrained-unevaluatedProperties` only
  fire for `openapi: 3.1.x` documents — confirmed the identical
  `unevaluatedProperties: true` node produces zero findings under
  `openapi: 3.0.3` but fires correctly once the same document's version
  is changed to `3.1.0`, nothing else. `unevaluatedProperties` is a
  JSON Schema 2019-09+ keyword the OAS 3.0 schema dialect doesn't
  recognize, which the ruleset appears to gate on internally.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SpectralRule:
    rule_id: str
    title: str
    problem: str
    impact: str
    recommendation: str
    references: list[dict]
    severity: str
    confidence: int


_WRITE_UNPROTECTED_REFS = [{"standard": "CWE", "id": "CWE-862"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
_READ_UNPROTECTED_REFS = [{"standard": "CWE", "id": "CWE-862"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
_MASS_ASSIGNMENT_REFS = [{"standard": "CWE", "id": "CWE-915"}, {"standard": "OWASP-API-Top10", "id": "API3:2023"}]
_RATE_LIMIT_REFS = [{"standard": "CWE", "id": "CWE-400"}, {"standard": "OWASP-API-Top10", "id": "API4:2023"}]
_SCHEMA_BOUNDS_REFS = [{"standard": "CWE", "id": "CWE-400"}, {"standard": "OWASP-API-Top10", "id": "API4:2023"}]
_HTTP_BASIC_REFS = [{"standard": "CWE", "id": "CWE-522"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
_CREDENTIALS_IN_URL_REFS = [{"standard": "CWE", "id": "CWE-598"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
_INSECURE_AUTH_SCHEME_REFS = [{"standard": "CWE", "id": "CWE-287"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
_JWT_BCP_REFS = [{"standard": "CWE", "id": "CWE-345"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
_LONG_LIVED_TOKEN_REFS = [{"standard": "CWE", "id": "CWE-613"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
_PREDICTABLE_ID_REFS = [{"standard": "CWE", "id": "CWE-639"}, {"standard": "OWASP-API-Top10", "id": "API1:2023"}]
_SSRF_URL_PARAM_REFS = [{"standard": "CWE", "id": "CWE-918"}, {"standard": "OWASP-API-Top10", "id": "API7:2023"}]
_ADMIN_ENDPOINT_REFS = [{"standard": "CWE", "id": "CWE-862"}, {"standard": "OWASP-API-Top10", "id": "API5:2023"}]
_OPEN_CORS_REFS = [{"standard": "CWE", "id": "CWE-942"}, {"standard": "OWASP-API-Top10", "id": "API8:2023"}]
_INSECURE_TRANSPORT_REFS = [{"standard": "CWE", "id": "CWE-319"}, {"standard": "OWASP-API-Top10", "id": "API8:2023"}]

_WRITE_UNPROTECTED = SpectralRule(
    rule_id="api.write-operation-unprotected",
    title="Write operation (POST/PUT/PATCH/DELETE) has no security scheme",
    problem=(
        "This write operation is not protected by any security scheme — neither an operation-level `security` "
        "requirement nor a global one from the spec's top-level `security` applies to it."
    ),
    impact=(
        "Any client, authenticated or not, can create/modify/delete data through this endpoint. For a write "
        "operation this is almost always exploitable directly, not just a hardening gap."
    ),
    recommendation=(
        "Add a `security` requirement referencing a scheme declared in `components.securitySchemes` to this "
        "operation (or the spec's global `security`, if every write operation should share it)."
    ),
    references=_WRITE_UNPROTECTED_REFS,
    severity="High",
    confidence=80,
)

_READ_UNPROTECTED = SpectralRule(
    rule_id="api.read-operation-unprotected",
    title="Read operation (GET/HEAD) has no security scheme",
    problem=(
        "This read operation is not protected by any security scheme. Some read endpoints are intentionally "
        "public (e.g. a health check or public catalog) — this is a lower-confidence signal than the write-side "
        "equivalent, not an automatic vulnerability."
    ),
    impact=(
        "If this data was not intended to be public, any client can read it without authentication — an "
        "information-disclosure risk whose severity depends entirely on what the endpoint returns."
    ),
    recommendation=(
        "Confirm whether this read operation is meant to be public. If not, add a `security` requirement "
        "matching the rest of the API's protected endpoints."
    ),
    references=_READ_UNPROTECTED_REFS,
    severity="Medium",
    confidence=55,
)

_MASS_ASSIGNMENT_ADDITIONAL = SpectralRule(
    rule_id="api.mass-assignment-additional-properties",
    title="Request/response schema does not restrict additionalProperties",
    problem=(
        "This object schema explicitly allows additional properties (`additionalProperties: true`, or an "
        "unconstrained sub-schema) instead of restricting them, so the schema itself does not limit which fields "
        "a client may submit."
    ),
    impact=(
        "A client can submit fields the API's contract never declared (e.g. `isAdmin`, `role`, `balance`) — if "
        "the implementation binds the request body directly onto an internal model without its own allow-list, "
        "this is a mass-assignment vulnerability the spec itself fails to rule out."
    ),
    recommendation=(
        "Set `additionalProperties: false` on request-body schemas that should only accept explicitly declared "
        "fields."
    ),
    references=_MASS_ASSIGNMENT_REFS,
    severity="Medium",
    confidence=60,
)

_MASS_ASSIGNMENT_UNEVALUATED = SpectralRule(
    rule_id="api.mass-assignment-unevaluated-properties",
    title="Request/response schema does not restrict unevaluatedProperties",
    problem=(
        "This object schema (using `allOf`/`oneOf`/`$ref` composition) does not set `unevaluatedProperties: "
        "false`, so properties not evaluated by any of the composed subschemas are still implicitly allowed."
    ),
    impact=(
        "Same underlying risk as unconstrained `additionalProperties` — a client can submit fields the composed "
        "schema never actually validates, and an implementation that trusts the schema's completeness may bind "
        "them onto an internal model unguarded."
    ),
    recommendation="Set `unevaluatedProperties: false` alongside schema composition keywords (`allOf`/`oneOf`/`anyOf`).",
    references=_MASS_ASSIGNMENT_REFS,
    severity="Medium",
    confidence=60,
)

_MISSING_RATE_LIMITING = SpectralRule(
    rule_id="api.missing-rate-limiting",
    title="Operation does not document rate-limiting behavior",
    problem=(
        "This operation's responses do not declare rate-limiting headers (e.g. `X-RateLimit-*`) on 2XX/4XX "
        "responses, a `429` response, or a `Retry-After` header on that `429` — the spec gives no evidence the "
        "API enforces or documents any request-rate ceiling."
    ),
    impact=(
        "Without rate limiting, this endpoint is exposed to resource-exhaustion abuse (credential stuffing, "
        "scraping, brute force) with no documented client-facing backpressure signal."
    ),
    recommendation=(
        "Enforce rate limiting at the gateway/application layer and document it: rate-limit headers on normal "
        "responses, a `429` response with a `Retry-After` header."
    ),
    references=_RATE_LIMIT_REFS,
    severity="Medium",
    confidence=50,
)

_UNBOUNDED_SCHEMA = SpectralRule(
    rule_id="api.unbounded-schema-resource-consumption",
    title="Schema does not bound array/string/integer size",
    problem=(
        "An array/string/integer schema does not declare a bound (`maxItems`; `maxLength`/`enum`/`const`; "
        "`minimum`+`maximum`, or a numeric `format`) that would cap the size or range of client-supplied values."
    ),
    impact=(
        "An unbounded array/string/integer in a request body lets a client submit arbitrarily large payloads or "
        "extreme numeric values, contributing to resource-exhaustion risk (OWASP API4:2023) at the "
        "parsing/validation layer even before any rate limit is reached."
    ),
    recommendation=(
        "Add explicit bounds to the schema: `maxItems` for arrays; `maxLength`/`enum`/`const`/`pattern` for "
        "strings; `minimum`/`maximum`/`format` for integers."
    ),
    references=_SCHEMA_BOUNDS_REFS,
    severity="Low",
    confidence=40,
)

_HTTP_BASIC = SpectralRule(
    rule_id="api.insecure-http-basic-auth",
    title="Security scheme uses HTTP Basic authentication",
    problem="A declared security scheme uses HTTP Basic authentication.",
    impact=(
        "Basic auth transmits credentials on every request (base64-encoded, not encrypted) and has no built-in "
        "expiration/rotation — credentials are far more exposed to interception/replay than a token-based scheme."
    ),
    recommendation="Replace HTTP Basic with OAuth 2 or OpenID Connect.",
    references=_HTTP_BASIC_REFS,
    severity="High",
    confidence=75,
)

_CREDENTIALS_IN_URL = SpectralRule(
    rule_id="api.credentials-in-url",
    title="API key or credential passed via URL (path/query parameter)",
    problem="An API key, password, or other credential is passed as a path or query parameter rather than a header.",
    impact=(
        "URLs are routinely logged by proxies, load balancers, browser history, and referrer headers — a "
        "credential embedded in one leaks through all of those channels, not just a direct network capture."
    ),
    recommendation="Pass credentials via a header (e.g. `Authorization`) or a secure cookie, never a URL parameter.",
    references=_CREDENTIALS_IN_URL_REFS,
    severity="High",
    confidence=75,
)

_INSECURE_AUTH_SCHEME = SpectralRule(
    rule_id="api.insecure-auth-scheme",
    title="Security scheme uses an outdated or insecure HTTP authentication scheme",
    problem="A declared security scheme uses an HTTP authentication scheme considered outdated or insecure (e.g. Negotiate, Digest).",
    impact="These schemes have known cryptographic or protocol weaknesses relative to modern alternatives (OAuth 2, OpenID Connect).",
    recommendation="Replace the scheme with OAuth 2 or OpenID Connect.",
    references=_INSECURE_AUTH_SCHEME_REFS,
    severity="Medium",
    confidence=55,
)

_JWT_BCP = SpectralRule(
    rule_id="api.jwt-missing-bcp-declaration",
    title="JWT-based security scheme does not declare RFC 8725 (JWT BCP) support",
    problem=(
        "A security scheme using JWTs (bearer tokens) does not mention RFC 8725 (JWT Best Current Practices) in "
        "its description — the spec gives no evidence the API's JWT handling follows the current best-practice "
        "guidance (algorithm confusion, `none`-algorithm, key confusion)."
    ),
    impact=(
        "This is a documentation gap, not a proven vulnerability by itself — but it correlates with APIs that "
        "haven't reviewed their JWT validation logic against known bypass classes. See detectors/auth (023) for "
        "the deterministic code-level JWT-bypass checks (weak/`none` algorithm, unverified signature) this "
        "finding does not duplicate."
    ),
    recommendation="Document RFC 8725 support in the security scheme's description, and verify the implementation actually follows it.",
    references=_JWT_BCP_REFS,
    severity="Low",
    confidence=35,
)

_LONG_LIVED_TOKEN = SpectralRule(
    rule_id="api.long-lived-access-tokens",
    title="OAuth2 security scheme does not appear to support refresh tokens",
    problem="An OAuth2 security scheme does not declare a flow that includes a refresh-token mechanism.",
    impact="Without refresh tokens, access tokens likely have long or no expiration, extending the window a leaked token remains usable.",
    recommendation="Use short-lived access tokens with a refresh-token flow instead of long-lived (or non-expiring) access tokens.",
    references=_LONG_LIVED_TOKEN_REFS,
    severity="Low",
    confidence=40,
)

_PREDICTABLE_ID = SpectralRule(
    rule_id="api.predictable-resource-ids",
    title="Resource identifier uses a sequential/numeric ID rather than a random one",
    problem="A path parameter identifying a resource (e.g. `/users/{id}`) uses a numeric (sequential/guessable) ID rather than a random one (e.g. a UUID).",
    impact=(
        "Sequential/numeric IDs are trivially enumerable — combined with a missing or weak per-object "
        "authorization check, an attacker can iterate IDs to access other users' resources (IDOR)."
    ),
    recommendation="Use a UUID (or another sufficiently random identifier) for resource IDs referenced in URLs.",
    references=_PREDICTABLE_ID_REFS,
    severity="Medium",
    confidence=45,
)

_SSRF_URL_PARAM = SpectralRule(
    rule_id="api.ssrf-prone-url-parameter",
    title="Parameter name suggests the API fetches a client-supplied URL server-side",
    problem="A parameter's name (e.g. `url`, `webhook`, `callback`, `redirect`) suggests the API uses a client-supplied URL for a server-side action (webhook registration, file fetch, SSO callback, URL preview, redirect).",
    impact="If the implementation fetches or redirects to this URL without validating it against an allow-list, an attacker can reach internal-only services, cloud metadata endpoints, or other hosts the API server can reach but the attacker cannot (SSRF).",
    recommendation="Validate the URL against an explicit allow-list of hosts/schemes before the server makes any request to it, or resolves/redirects based on it.",
    references=_SSRF_URL_PARAM_REFS,
    severity="Medium",
    confidence=40,
)

_ADMIN_ENDPOINT = SpectralRule(
    rule_id="api.admin-endpoint-not-isolated",
    title="Admin-facing operation is not clearly isolated from regular API surface",
    problem="An operation appears to be admin-facing but is not clearly distinguished (via a distinct security scheme, tag, or path prefix) from the rest of the API surface.",
    impact="Broken Function Level Authorization (OWASP API5:2023): if admin functions share the same authorization boundary as regular user functions, a regular authenticated user may be able to reach administrative actions.",
    recommendation="Require a distinct, more privileged security scheme (or role/scope) for admin operations, and isolate them under a clearly distinct path prefix or tag.",
    references=_ADMIN_ENDPOINT_REFS,
    severity="High",
    confidence=45,
)

_OPEN_CORS = SpectralRule(
    rule_id="api.open-cors-policy",
    title="CORS header not defined for this response",
    problem="This operation's response does not declare a CORS header (e.g. `Access-Control-Allow-Origin`), leaving the actual CORS policy undocumented in the spec.",
    impact="An overly permissive CORS policy (wildcard origin combined with credentials) lets any website make authenticated cross-origin requests on a victim's behalf — a common real-world API misconfiguration.",
    recommendation="Document the intended CORS policy explicitly, and verify the implementation restricts `Access-Control-Allow-Origin` to a specific, trusted set of origins (never a wildcard alongside credentialed requests).",
    references=_OPEN_CORS_REFS,
    severity="High",
    confidence=45,
)

_INSECURE_TRANSPORT = SpectralRule(
    rule_id="api.insecure-transport",
    title="Server or scheme declares plain HTTP instead of HTTPS",
    problem="A server URL or scheme uses `http://` instead of `https://` (or `wss://`).",
    impact="Traffic to/from this server is unencrypted — credentials, tokens, and any sensitive data in requests or responses can be intercepted or modified in transit.",
    recommendation="Use `https://` (or `wss://` for websockets) for every server URL and scheme; do not offer plain HTTP as an option.",
    references=_INSECURE_TRANSPORT_REFS,
    severity="High",
    confidence=85,
)

# Maps every curated Spectral rule *code* (there can be more than one
# code per rule_id, see module docstring) to its SpectralRule. Codes
# not present here (either the ruleset's own uncurated codes, or its
# "parser"-level pseudo-findings for a malformed spec) are silently
# skipped by scanner.py — same "curate a subset, skip the rest"
# precedent as 009/010/011.
SPECTRAL_CODE_TO_RULE: dict[str, SpectralRule] = {
    "owasp:api2:2023-write-restricted": _WRITE_UNPROTECTED,
    "owasp:api2:2023-read-restricted": _READ_UNPROTECTED,
    "owasp:api3:2023-no-additionalProperties": _MASS_ASSIGNMENT_ADDITIONAL,
    "owasp:api3:2023-constrained-additionalProperties": _MASS_ASSIGNMENT_ADDITIONAL,
    "owasp:api3:2023-no-unevaluatedProperties": _MASS_ASSIGNMENT_UNEVALUATED,
    "owasp:api3:2023-constrained-unevaluatedProperties": _MASS_ASSIGNMENT_UNEVALUATED,
    "owasp:api4:2023-rate-limit": _MISSING_RATE_LIMITING,
    "owasp:api4:2023-rate-limit-retry-after": _MISSING_RATE_LIMITING,
    "owasp:api4:2023-rate-limit-responses-429": _MISSING_RATE_LIMITING,
    "owasp:api4:2023-array-limit": _UNBOUNDED_SCHEMA,
    "owasp:api4:2023-string-limit": _UNBOUNDED_SCHEMA,
    "owasp:api4:2023-string-restricted": _UNBOUNDED_SCHEMA,
    "owasp:api4:2023-integer-limit": _UNBOUNDED_SCHEMA,
    "owasp:api4:2023-integer-limit-legacy": _UNBOUNDED_SCHEMA,
    "owasp:api4:2023-integer-format": _UNBOUNDED_SCHEMA,
    "owasp:api2:2023-no-http-basic": _HTTP_BASIC,
    "owasp:api2:2023-no-api-keys-in-url": _CREDENTIALS_IN_URL,
    "owasp:api2:2023-no-credentials-in-url": _CREDENTIALS_IN_URL,
    "owasp:api2:2023-auth-insecure-schemes": _INSECURE_AUTH_SCHEME,
    "owasp:api2:2023-jwt-best-practices": _JWT_BCP,
    "owasp:api2:2023-short-lived-access-tokens": _LONG_LIVED_TOKEN,
    "owasp:api1:2023-no-numeric-ids": _PREDICTABLE_ID,
    "owasp:api7:2023-concerning-url-parameter": _SSRF_URL_PARAM,
    "owasp:api5:2023-admin-security-unique": _ADMIN_ENDPOINT,
    "owasp:api8:2023-define-cors-origin": _OPEN_CORS,
    "owasp:api8:2023-no-scheme-http": _INSECURE_TRANSPORT,
    "owasp:api8:2023-no-server-http": _INSECURE_TRANSPORT,
}
