"""Tests for crossref.py: playbook guidance rendering and the
finding-builder helper for this plan's spec-aware cross-reference
mechanism (deterministic spec extraction + agent-guided code
correlation — see crossref.py's module docstring for why this mirrors
detectors/auth's (023) hybrid precedent rather than a bespoke
per-framework route extractor).

Run with: python3 -m unittest test_crossref -v (from inside
detectors/api/).
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import crossref
from spec_analysis import load_and_extract, secured_operations

SPEC_WITH_ONE_SECURED_ONE_UNSECURED = """openapi: 3.0.3
info:
  title: X
  version: "1.0"
paths:
  /admin/users/{id}:
    delete:
      operationId: deleteUser
      security:
        - apiKeyAuth: []
      responses:
        '200':
          description: OK
  /public/health:
    get:
      operationId: health
      security: []
      responses:
        '200':
          description: OK
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
"""

SPEC_WITH_NOTHING_SECURED = """openapi: 3.0.3
info:
  title: X
  version: "1.0"
paths:
  /public:
    get:
      operationId: pub
      security: []
      responses:
        '200':
          description: OK
"""


class RenderGuidanceTests(unittest.TestCase):
    def _secured_ops(self, spec_text: str, tmp: str):
        path = Path(tmp) / "spec.yaml"
        path.write_text(spec_text, encoding="utf-8")
        return secured_operations(load_and_extract(path)), str(path)

    def test_lists_only_secured_operations_with_scheme_and_location(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ops, spec_file = self._secured_ops(SPEC_WITH_ONE_SECURED_ONE_UNSECURED, tmp)
            guidance = crossref.render_guidance(ops, spec_file)

        self.assertIn("DELETE /admin/users/{id}", guidance)
        self.assertIn("apiKeyAuth", guidance)
        self.assertNotIn("/public/health", guidance)
        self.assertIn(crossref.RULE_ID, guidance)
        self.assertIn("CWE CWE-862", guidance)

    def test_no_secured_operations_returns_explanatory_message_not_empty_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ops, spec_file = self._secured_ops(SPEC_WITH_NOTHING_SECURED, tmp)
            guidance = crossref.render_guidance(ops, spec_file)

        self.assertNotEqual(guidance.strip(), "")
        self.assertIn("nothing to cross-reference", guidance)


class BuildFindingTests(unittest.TestCase):
    def _one_secured_op(self, tmp: str):
        path = Path(tmp) / "spec.yaml"
        path.write_text(SPEC_WITH_ONE_SECURED_ONE_UNSECURED, encoding="utf-8")
        ops = secured_operations(load_and_extract(path))
        return ops[0], str(path)

    def test_build_finding_is_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            op, spec_file = self._one_secured_op(tmp)
            finding = crossref.build_finding(op, spec_file, "app/routes/users.py", 42, 45)

        errors = crossref.validate_finding(finding)
        self.assertEqual(errors, [])
        self.assertEqual(finding["ruleId"], crossref.RULE_ID)
        self.assertEqual(finding["subSkill"], "api")
        self.assertEqual(finding["artifactType"], "source-code")
        self.assertEqual(finding["location"], {"file": "app/routes/users.py", "startLine": 42, "endLine": 45})
        self.assertEqual(finding["metadata"]["specPath"], "/admin/users/{id}")
        self.assertEqual(finding["metadata"]["specMethod"], "delete")
        self.assertEqual(finding["metadata"]["requiredSecuritySchemes"], ["apiKeyAuth"])

    def test_build_finding_defaults_end_line_to_start_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            op, spec_file = self._one_secured_op(tmp)
            finding = crossref.build_finding(op, spec_file, "app/routes/users.py", 42)
        self.assertEqual(finding["location"]["endLine"], 42)

    def test_validator_actually_rejects_an_invalid_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            op, spec_file = self._one_secured_op(tmp)
            finding = crossref.build_finding(op, spec_file, "app/routes/users.py", 42)
        del finding["severity"]
        errors = crossref.validate_finding(finding)
        self.assertNotEqual(errors, [])

    def test_two_different_operations_get_different_finding_ids(self) -> None:
        spec_with_two = SPEC_WITH_ONE_SECURED_ONE_UNSECURED.replace(
            "security: []", "security:\n        - apiKeyAuth: []", 1
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.yaml"
            path.write_text(spec_with_two, encoding="utf-8")
            ops = secured_operations(load_and_extract(path))
        self.assertEqual(len(ops), 2)
        f1 = crossref.build_finding(ops[0], str(path), "handlers.py", 10)
        f2 = crossref.build_finding(ops[1], str(path), "handlers.py", 10)
        self.assertNotEqual(f1["findingId"], f2["findingId"])


class MainCliTests(unittest.TestCase):
    def test_renders_guidance_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.yaml"
            path.write_text(SPEC_WITH_ONE_SECURED_ONE_UNSECURED, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = crossref.main([str(path)])
        self.assertEqual(code, 0)
        self.assertIn("/admin/users/{id}", out.getvalue())

    def test_malformed_spec_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("openapi: 3.0.3\n  bad indent: [", encoding="utf-8")
            code = crossref.main([str(path)])
        self.assertEqual(code, 1)


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

        detector_dir = Path(__file__).parent
        violations = []
        for path in sorted(detector_dir.glob("*.py")):
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
