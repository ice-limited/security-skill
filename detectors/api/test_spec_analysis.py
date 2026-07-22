"""Tests for spec_analysis.py: pure OpenAPI parsing, no subprocess —
global-vs-operation-level `security` inheritance, explicit `security:
[]` overrides, ruamel.yaml line-number extraction, and malformed-input
error handling.

Run with: python3 -m unittest test_spec_analysis -v (from inside
detectors/api/).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spec_analysis import SpecParseError, extract_operations, load_and_extract, load_spec, secured_operations

SPEC_WITH_GLOBAL_SECURITY = """openapi: 3.0.3
info:
  title: X
  version: "1.0"
security:
  - apiKeyAuth: []
paths:
  /inherits-global/{id}:
    get:
      operationId: inheritsGlobal
      responses:
        '200':
          description: OK
  /explicit-override:
    get:
      operationId: explicitOverride
      security: []
      responses:
        '200':
          description: OK
  /operation-specific:
    post:
      operationId: operationSpecific
      security:
        - oauthAuth: []
      parameters:
        - name: q
          in: query
          schema:
            type: string
      responses:
        '200':
          description: OK
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    oauthAuth:
      type: oauth2
      flows: {}
"""

SPEC_WITH_NO_GLOBAL_SECURITY = """openapi: 3.0.3
info:
  title: X
  version: "1.0"
paths:
  /unsecured:
    get:
      operationId: unsecured
      responses:
        '200':
          description: OK
"""

NOT_A_MAPPING = "- just\n- a\n- list\n"

MALFORMED_YAML = "openapi: 3.0.3\n  bad indent: ["


class LoadSpecTests(unittest.TestCase):
    def test_loads_valid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.yaml"
            path.write_text(SPEC_WITH_GLOBAL_SECURITY, encoding="utf-8")
            doc = load_spec(path)
        self.assertEqual(doc["openapi"], "3.0.3")

    def test_loads_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.json"
            path.write_text('{"openapi": "3.0.3", "paths": {}}', encoding="utf-8")
            doc = load_spec(path)
        self.assertEqual(doc["openapi"], "3.0.3")

    def test_malformed_yaml_raises_spec_parse_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text(MALFORMED_YAML, encoding="utf-8")
            with self.assertRaises(SpecParseError):
                load_spec(path)

    def test_non_mapping_top_level_raises_spec_parse_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.yaml"
            path.write_text(NOT_A_MAPPING, encoding="utf-8")
            with self.assertRaises(SpecParseError):
                load_spec(path)


class ExtractOperationsTests(unittest.TestCase):
    def _operations_by_path(self, spec_text: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.yaml"
            path.write_text(spec_text, encoding="utf-8")
            ops = extract_operations(load_spec(path))
        return {(op.path, op.method): op for op in ops}

    def test_operation_with_no_security_key_inherits_global(self) -> None:
        ops = self._operations_by_path(SPEC_WITH_GLOBAL_SECURITY)
        op = ops[("/inherits-global/{id}", "get")]
        self.assertTrue(op.is_secured)
        self.assertEqual(op.security_schemes, ("apiKeyAuth",))
        self.assertFalse(op.explicitly_unsecured)

    def test_operation_with_explicit_empty_security_is_not_secured(self) -> None:
        ops = self._operations_by_path(SPEC_WITH_GLOBAL_SECURITY)
        op = ops[("/explicit-override", "get")]
        self.assertFalse(op.is_secured)
        self.assertTrue(op.explicitly_unsecured)

    def test_operation_specific_security_overrides_global(self) -> None:
        ops = self._operations_by_path(SPEC_WITH_GLOBAL_SECURITY)
        op = ops[("/operation-specific", "post")]
        self.assertEqual(op.security_schemes, ("oauthAuth",))

    def test_no_global_security_and_no_operation_security_is_unsecured(self) -> None:
        ops = self._operations_by_path(SPEC_WITH_NO_GLOBAL_SECURITY)
        op = ops[("/unsecured", "get")]
        self.assertFalse(op.is_secured)
        self.assertFalse(op.explicitly_unsecured)

    def test_non_method_keys_under_a_path_item_are_not_misidentified(self) -> None:
        ops = self._operations_by_path(SPEC_WITH_GLOBAL_SECURITY)
        methods_seen = {method for (_, method) in ops}
        self.assertNotIn("parameters", methods_seen)
        self.assertNotIn("summary", methods_seen)

    def test_line_numbers_are_1_indexed_and_point_at_the_method_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.yaml"
            path.write_text(SPEC_WITH_GLOBAL_SECURITY, encoding="utf-8")
            ops = extract_operations(load_spec(path))
        op = next(o for o in ops if o.path == "/inherits-global/{id}")
        lines = SPEC_WITH_GLOBAL_SECURITY.splitlines()
        self.assertEqual(lines[op.line - 1].strip(), "get:")

    def test_secured_operations_filters_to_only_secured_ones(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.yaml"
            path.write_text(SPEC_WITH_GLOBAL_SECURITY, encoding="utf-8")
            secured = secured_operations(load_and_extract(path))
        self.assertEqual({op.path for op in secured}, {"/inherits-global/{id}", "/operation-specific"})

    def test_no_paths_key_returns_empty_list(self) -> None:
        self.assertEqual(extract_operations({"openapi": "3.0.3"}), [])

    def test_non_dict_path_item_is_skipped_not_crashed_on(self) -> None:
        spec = {"paths": {"/weird": None}}
        self.assertEqual(extract_operations(spec), [])


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
