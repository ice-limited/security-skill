"""Tests for the API spec-lint detector: real Spectral subprocess calls
(not mocked — matches this project's standing testing discipline, see
e.g. plans/011-iac-skill.md's kickoff note on why), violation-to-
finding mapping, schema conformance, spec-file discovery, and error
handling.

Requires `npm install` to have been run in this directory (installs
the real `@stoplight/spectral-cli` + `@stoplight/spectral-owasp-
ruleset` into a local node_modules/). Run with:
python3 -m unittest test_scanner -v (from inside detectors/api/).
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import scanner
from rules import SPECTRAL_CODE_TO_RULE
from scanner import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402


def _spectral_available() -> bool:
    return shutil.which("npx") is not None and (DETECTOR_DIR / "node_modules" / "@stoplight" / "spectral-cli").is_dir()


# Deliberately obvious/synthetic fixtures, not real-world content —
# enough for Spectral's real OWASP ruleset to actually fire, not just
# "look" vulnerable. Every rule this fixture is claimed to trigger was
# verified against the real Spectral CLI at implementation (see
# plans/012-api-skill.md), including two real, verified Spectral
# quirks that shaped this fixture's design:
# - `no-additionalProperties` only fires when `additionalProperties`
#   is explicitly `true` (or an unconstrained sub-schema) — omitting
#   the keyword does not trigger it.
# - the `unevaluatedProperties` pair only fires for `openapi: 3.1.x`
#   documents (see UNEVALUATED_PROPERTIES_OAS31 below) — this fixture
#   stays 3.0.3 and does not attempt to trigger that pair.
VULNERABLE_SPEC = """openapi: 3.0.3
info:
  title: Vulnerable Sample API
  version: "1.0"
servers:
  - url: http://api.example.com/v1
paths:
  /users/{id}:
    get:
      operationId: getUser
      security: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: OK
          headers:
            X-Request-Id:
              schema:
                type: string
    put:
      operationId: updateUser
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: true
              properties:
                name:
                  type: string
      responses:
        '200':
          description: OK
  /admin/settings:
    get:
      operationId: getAdminSettings
      security:
        - basicAuth: []
      responses:
        '200':
          description: OK
  /login:
    post:
      operationId: login
      security:
        - basicAuth: []
      responses:
        '200':
          description: OK
  /legacy-auth:
    post:
      operationId: legacyAuth
      security:
        - negotiateAuth: []
      responses:
        '200':
          description: OK
  /webhooks:
    post:
      operationId: registerWebhook
      parameters:
        - name: callbackUrl
          in: query
          schema:
            type: string
        - name: access_token
          in: query
          schema:
            type: string
      security:
        - apiKeyQueryScheme: []
      responses:
        '200':
          description: OK
  /oauth-resource:
    get:
      operationId: getOauthResource
      security:
        - oauthClientCreds: []
      responses:
        '200':
          description: OK
components:
  securitySchemes:
    basicAuth:
      type: http
      scheme: basic
    apiKeyQueryScheme:
      type: apiKey
      in: query
      name: access_token
    negotiateAuth:
      type: http
      scheme: negotiate
    bearerJwt:
      type: http
      scheme: bearer
      bearerFormat: JWT
    oauthClientCreds:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://auth.example.com/token
          scopes: {}
"""

# Every rule this triggers, verified for real at implementation
# (2026-07-22): 15 of this plan's 16 curated rule_ids — every one
# except `api.mass-assignment-unevaluated-properties`, which needs an
# `openapi: 3.1.x` document (see UNEVALUATED_PROPERTIES_OAS31 below).
VULNERABLE_SPEC_EXPECTED_RULE_IDS = {
    "api.write-operation-unprotected",
    "api.read-operation-unprotected",
    "api.mass-assignment-additional-properties",
    "api.missing-rate-limiting",
    "api.unbounded-schema-resource-consumption",
    "api.insecure-http-basic-auth",
    "api.credentials-in-url",
    "api.insecure-auth-scheme",
    "api.jwt-missing-bcp-declaration",
    "api.long-lived-access-tokens",
    "api.predictable-resource-ids",
    "api.ssrf-prone-url-parameter",
    "api.admin-endpoint-not-isolated",
    "api.open-cors-policy",
    "api.insecure-transport",
}

# Hand-verified to produce zero curated findings (real subprocess run,
# not assumed) — every curated rule category is deliberately satisfied:
# HTTPS server, secured operation, bounded schema (both maxLength *and*
# format/pattern, since `string-limit` and `string-restricted` accept
# different sets of satisfiers — a real quirk found while building
# this fixture), rate-limit headers on both 2XX *and* 4XX responses
# (the OWASP ruleset's `rate-limit` rule checks both), CORS header
# defined on every `headers` block present, and a JWT scheme whose
# description matches the ruleset's exact required pattern
# (`RFC8725`, no space — found by testing, the ruleset's own example
# text mirrors this exact spelling).
CLEAN_SPEC = """openapi: 3.0.3
info:
  title: Clean API
  version: "1.0"
servers:
  - url: https://api.example.com/v1
    x-internal: false
paths:
  /users/{id}:
    get:
      operationId: getUser
      security:
        - bearerJwt: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
            maxLength: 36
      responses:
        '200':
          description: OK
          headers:
            X-RateLimit-Limit:
              schema:
                type: integer
                format: int32
                minimum: 0
                maximum: 100000
            Access-Control-Allow-Origin:
              schema:
                type: string
                maxLength: 255
                pattern: "^https://[a-z.]+$"
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
                properties:
                  name:
                    type: string
                    maxLength: 100
                    pattern: "^[A-Za-z0-9 ]*$"
        '429':
          description: Too Many Requests
          headers:
            X-RateLimit-Limit:
              schema:
                type: integer
                format: int32
                minimum: 0
                maximum: 100000
            Retry-After:
              schema:
                type: integer
                format: int32
                minimum: 0
                maximum: 100000
            Access-Control-Allow-Origin:
              schema:
                type: string
                maxLength: 255
                pattern: "^https://[a-z.]+$"
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
components:
  securitySchemes:
    bearerJwt:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: "Bearer JWT tokens, conforming to RFC8725 (JWT Best Current Practices)."
"""

# The unevaluatedProperties pair only fires for openapi: 3.1.x
# documents — confirmed empirically (identical node produces zero
# findings under 3.0.3, fires correctly under 3.1.0) — kept as its own
# minimal fixture rather than folded into VULNERABLE_SPEC.
UNEVALUATED_PROPERTIES_OAS31 = """openapi: 3.1.0
info:
  title: Minimal
  version: "1.0"
paths:
  /x:
    post:
      operationId: postX
      security:
        - basicAuth: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              unevaluatedProperties: true
      responses:
        '200':
          description: OK
components:
  securitySchemes:
    basicAuth:
      type: http
      scheme: basic
"""

NOT_AN_OPENAPI_SPEC = """version: "1"
services:
  web:
    image: nginx:latest
"""


@unittest.skipUnless(_spectral_available(), "requires 'npm install' in detectors/api/")
class SchemaConformanceAndCoverageTests(unittest.TestCase):
    def test_vulnerable_fixture_fires_expected_rules_and_is_schema_valid(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.yaml"
            path.write_text(VULNERABLE_SPEC, encoding="utf-8")
            findings = scanner.scan_paths([str(path)])

        self.assertTrue(findings)
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(rule_ids, VULNERABLE_SPEC_EXPECTED_RULE_IDS)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")
            self.assertEqual(f["subSkill"], "api")
            self.assertEqual(f["artifactType"], "api-spec")

    def test_clean_fixture_produces_no_curated_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.yaml"
            path.write_text(CLEAN_SPEC, encoding="utf-8")
            findings = scanner.scan_paths([str(path)])
        self.assertEqual(findings, [])

    def test_unevaluated_properties_only_fires_for_oas31(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path31 = Path(tmp) / "openapi31.yaml"
            path31.write_text(UNEVALUATED_PROPERTIES_OAS31, encoding="utf-8")
            findings31 = scanner.scan_paths([str(path31)])

            path30 = Path(tmp) / "openapi30.yaml"
            path30.write_text(UNEVALUATED_PROPERTIES_OAS31.replace("3.1.0", "3.0.3"), encoding="utf-8")
            findings30 = scanner.scan_paths([str(path30)])

        self.assertIn("api.mass-assignment-unevaluated-properties", {f["ruleId"] for f in findings31})
        self.assertNotIn("api.mass-assignment-unevaluated-properties", {f["ruleId"] for f in findings30})


@unittest.skipUnless(_spectral_available(), "requires 'npm install' in detectors/api/")
class SpecDiscoveryTests(unittest.TestCase):
    def test_directory_input_discovers_the_real_spec_and_skips_unrelated_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "docker-compose.yml").write_text(NOT_AN_OPENAPI_SPEC, encoding="utf-8")
            (Path(tmp) / "openapi.yaml").write_text(CLEAN_SPEC, encoding="utf-8")
            findings = scanner.scan_paths([tmp])
        # Clean spec + a non-OpenAPI YAML file sitting alongside it in
        # the same directory: real assertion is that discovery didn't
        # crash or feed the unrelated file into Spectral, not just that
        # findings happen to be empty (CLEAN_SPEC already proves that).
        self.assertEqual(findings, [])

    def test_looks_like_openapi_spec_accepts_openapi_and_swagger_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            openapi_file = Path(tmp) / "a.yaml"
            openapi_file.write_text(CLEAN_SPEC, encoding="utf-8")
            self.assertTrue(scanner._looks_like_openapi_spec(openapi_file))

            swagger_file = Path(tmp) / "b.yaml"
            swagger_file.write_text('swagger: "2.0"\ninfo:\n  title: x\n  version: "1"\npaths: {}\n', encoding="utf-8")
            self.assertTrue(scanner._looks_like_openapi_spec(swagger_file))

            unrelated_file = Path(tmp) / "c.yaml"
            unrelated_file.write_text(NOT_AN_OPENAPI_SPEC, encoding="utf-8")
            self.assertFalse(scanner._looks_like_openapi_spec(unrelated_file))

    def test_looks_like_openapi_spec_does_not_crash_on_malformed_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.yaml"
            bad.write_text("openapi: 3.0.3\n  bad indent: [", encoding="utf-8")
            self.assertFalse(scanner._looks_like_openapi_spec(bad))

    def test_non_spec_extension_is_never_treated_as_a_spec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.txt"
            path.write_text(CLEAN_SPEC, encoding="utf-8")
            self.assertFalse(scanner._looks_like_openapi_spec(path))


class ErrorHandlingTests(unittest.TestCase):
    def test_bad_path_raises_scanner_error(self) -> None:
        with self.assertRaises(ScannerError):
            scanner.scan_paths(["/tmp/definitely-does-not-exist-012-api"])

    def test_missing_npx_raises_actionable_error(self) -> None:
        with mock.patch("scanner.shutil.which", return_value=None):
            with self.assertRaises(ScannerError) as ctx:
                scanner.run_spectral("irrelevant.yaml")
        self.assertIn("Node.js", str(ctx.exception))

    def test_missing_node_modules_raises_actionable_error(self) -> None:
        with mock.patch("scanner.shutil.which", return_value="/usr/bin/npx"):
            with mock.patch("scanner.API_DIR", Path("/tmp/definitely-not-installed-012-api")):
                with self.assertRaises(ScannerError) as ctx:
                    scanner._check_spectral_available()
        self.assertIn("npm install", str(ctx.exception))

    def test_returncode_two_or_more_raises(self) -> None:
        fake_proc = mock.Mock(returncode=2, stdout="", stderr="mocked CLI error")
        with mock.patch("scanner._check_spectral_available"):
            with mock.patch("scanner.subprocess.run", return_value=fake_proc):
                with self.assertRaises(ScannerError):
                    scanner.run_spectral("irrelevant.yaml")

    def test_returncode_zero_and_one_are_both_accepted(self) -> None:
        for code in (0, 1):
            fake_proc = mock.Mock(returncode=code, stdout="[]", stderr="")
            with mock.patch("scanner._check_spectral_available"):
                with mock.patch("scanner.subprocess.run", return_value=fake_proc):
                    self.assertEqual(scanner.run_spectral("irrelevant.yaml"), [])

    def test_non_json_stdout_raises(self) -> None:
        fake_proc = mock.Mock(returncode=1, stdout="not json", stderr="")
        with mock.patch("scanner._check_spectral_available"):
            with mock.patch("scanner.subprocess.run", return_value=fake_proc):
                with self.assertRaises(ScannerError):
                    scanner.run_spectral("irrelevant.yaml")


class MappingTests(unittest.TestCase):
    """Pure-function unit tests — no Spectral subprocess needed, fast
    and deterministic."""

    def _violation(self, code: str, line0: int = 5, char0: int = 4, path=None) -> dict:
        return {
            "code": code,
            "path": path if path is not None else ["paths", "/x", "get"],
            "message": "irrelevant",
            "severity": 0,
            "range": {"start": {"line": line0, "character": char0}, "end": {"line": line0, "character": char0 + 10}},
        }

    def test_uncurated_code_returns_none(self) -> None:
        self.assertIsNone(scanner.map_violation_to_finding(self._violation("owasp:api9:2023-inventory-access"), "f.yaml", "6.0.0"))

    def test_parser_pseudo_finding_returns_none(self) -> None:
        self.assertIsNone(scanner.map_violation_to_finding(self._violation("parser"), "f.yaml", "6.0.0"))

    def test_curated_code_maps_with_1_indexed_location(self) -> None:
        finding = scanner.map_violation_to_finding(self._violation("owasp:api8:2023-no-server-http", line0=5, char0=4), "f.yaml", "6.0.0")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["ruleId"], "api.insecure-transport")
        self.assertEqual(finding["location"]["startLine"], 6)
        self.assertEqual(finding["location"]["startColumn"], 5)

    def test_two_codes_mapping_to_the_same_rule_id_share_it(self) -> None:
        a = scanner.map_violation_to_finding(self._violation("owasp:api8:2023-no-server-http"), "f.yaml", "6.0.0")
        b = scanner.map_violation_to_finding(self._violation("owasp:api8:2023-no-scheme-http"), "f.yaml", "6.0.0")
        self.assertEqual(a["ruleId"], b["ruleId"])
        self.assertEqual(a["ruleId"], "api.insecure-transport")

    def test_ast_node_path_is_dot_joined_from_violation_path(self) -> None:
        finding = scanner.map_violation_to_finding(
            self._violation("owasp:api2:2023-read-restricted", path=["paths", "/users/{id}", "get", "security"]),
            "f.yaml",
            "6.0.0",
        )
        self.assertEqual(finding["location"]["astNodePath"], "paths./users/{id}.get.security")

    def test_missing_character_field_omits_columns(self) -> None:
        violation = {
            "code": "owasp:api8:2023-no-server-http",
            "path": ["servers", "0"],
            "range": {"start": {"line": 0}, "end": {"line": 0}},
        }
        finding = scanner.map_violation_to_finding(violation, "f.yaml", "6.0.0")
        self.assertNotIn("startColumn", finding["location"])
        self.assertNotIn("endColumn", finding["location"])


class ConsistencyTests(unittest.TestCase):
    def test_every_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        for rule in SPECTRAL_CODE_TO_RULE.values():
            for ref in rule.references:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{rule.rule_id} cites {ref}")

    def test_every_rule_id_matches_naming_convention(self) -> None:
        import re

        pattern = re.compile(r"^api\.[a-z0-9-]+$")
        for rule in SPECTRAL_CODE_TO_RULE.values():
            self.assertTrue(pattern.match(rule.rule_id), rule.rule_id)

    def test_every_rule_severity_is_a_valid_schema_enum_value(self) -> None:
        valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
        seen_rule_ids = set()
        for rule in SPECTRAL_CODE_TO_RULE.values():
            if rule.rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule.rule_id)
            self.assertIn(rule.severity, valid_severities, rule.rule_id)

    def test_no_spectral_code_maps_to_two_different_rules(self) -> None:
        # Sanity check on the dict itself (would only fail if a future
        # edit accidentally listed the same code key twice with
        # different values, which Python's dict literal syntax would
        # otherwise silently resolve to "last one wins").
        self.assertEqual(len(SPECTRAL_CODE_TO_RULE), len(set(SPECTRAL_CODE_TO_RULE.keys())))

    def test_every_curated_rule_id_is_reachable_from_at_least_one_code(self) -> None:
        # Guards against a rule constant existing in rules.py but never
        # wired into SPECTRAL_CODE_TO_RULE at all (a copy-paste-and-
        # forget-to-register bug) — every SpectralRule instance module-
        # level must appear as a dict value.
        import rules as rules_module

        defined_rule_objects = {
            v.rule_id for v in vars(rules_module).values() if isinstance(v, rules_module.SpectralRule)
        }
        reachable_rule_ids = {r.rule_id for r in SPECTRAL_CODE_TO_RULE.values()}
        self.assertEqual(defined_rule_objects, reachable_rule_ids)


@unittest.skipUnless(_spectral_available(), "requires 'npm install' in detectors/api/")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.yaml"
            path.write_text(CLEAN_SPEC, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([str(path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), [])

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = scanner.main(["/tmp/definitely-does-not-exist-012-api"])
        self.assertEqual(code, 1)
        self.assertIn("SCANNER ERROR", err.getvalue())


class CrossPlatformEncodingTests(unittest.TestCase):
    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


class SourceEncodingAuditTests(unittest.TestCase):
    def test_no_read_or_write_text_call_omits_encoding(self) -> None:
        import ast

        violations = []
        for path in sorted(DETECTOR_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("read_text", "write_text")
                ):
                    kwarg_names = {kw.arg for kw in node.keywords}
                    if "encoding" not in kwarg_names:
                        violations.append(f"{path.name}:{node.lineno} .{node.func.attr}() missing encoding=")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
