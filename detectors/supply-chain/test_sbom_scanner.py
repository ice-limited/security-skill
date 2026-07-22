"""Tests for SBOM validity: format detection (CycloneDX/SPDX, from a
file's own self-declared fields) and real JSON-Schema validation
against the vendored, official schemas — not a hand-rolled
approximation.

Run with: python3 -m unittest test_sbom_scanner -v (from inside
detectors/supply-chain/).
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import sbom_scanner
import sbom_validate
from sbom_scanner import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402

VALID_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [{"type": "library", "name": "requests", "version": "2.31.0"}],
}

INVALID_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": "not-a-number",
    "components": [{"type": "not-a-valid-type", "name": "requests"}],
}

VALID_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "example",
    "documentNamespace": "https://example.com/spdx/example-1",
    "creationInfo": {"created": "2026-07-22T00:00:00Z", "creators": ["Tool: syft-1.0"]},
    "dataLicense": "CC0-1.0",
}

INVALID_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "creationInfo": {"created": "not-a-date", "creators": "should-be-an-array"},
}

NOT_AN_SBOM = {"hello": "world"}


class DetectFormatTests(unittest.TestCase):
    def test_cyclonedx_detected(self) -> None:
        self.assertEqual(sbom_validate.detect_sbom_format(VALID_CYCLONEDX), "CycloneDX")

    def test_spdx_detected(self) -> None:
        self.assertEqual(sbom_validate.detect_sbom_format(VALID_SPDX), "SPDX")

    def test_unrelated_json_is_not_detected(self) -> None:
        self.assertIsNone(sbom_validate.detect_sbom_format(NOT_AN_SBOM))

    def test_non_dict_is_not_detected(self) -> None:
        self.assertIsNone(sbom_validate.detect_sbom_format(["not", "a", "dict"]))


class ScanFileTests(unittest.TestCase):
    def _write(self, tmp: str, doc: dict, name: str = "sbom.json") -> Path:
        path = Path(tmp) / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_valid_cyclonedx_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, VALID_CYCLONEDX)
            findings = sbom_scanner.scan_file(path)
        self.assertEqual(findings, [])

    def test_invalid_cyclonedx_produces_a_finding_with_real_schema_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, INVALID_CYCLONEDX)
            findings = sbom_scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ruleId"], "supply-chain.invalid-sbom")
        errors = findings[0]["metadata"]["schemaValidationErrors"]
        self.assertTrue(any("not-a-number" in e or "integer" in e for e in errors))

    def test_valid_spdx_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, VALID_SPDX)
            findings = sbom_scanner.scan_file(path)
        self.assertEqual(findings, [])

    def test_invalid_spdx_produces_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, INVALID_SPDX)
            findings = sbom_scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ruleId"], "supply-chain.invalid-sbom")

    def test_non_sbom_json_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, NOT_AN_SBOM)
            findings = sbom_scanner.scan_file(path)
        self.assertEqual(findings, [])

    def test_malformed_json_raises_scanner_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(ScannerError):
                sbom_scanner.scan_file(path)


class ScanPathsDiscoveryTests(unittest.TestCase):
    def test_directory_input_finds_the_sbom_and_skips_unrelated_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
            (Path(tmp) / "sbom.json").write_text(json.dumps(INVALID_CYCLONEDX), encoding="utf-8")
            findings = sbom_scanner.scan_paths([tmp])
        self.assertEqual(len(findings), 1)

    def test_bad_path_raises_scanner_error(self) -> None:
        with self.assertRaises(ScannerError):
            sbom_scanner.scan_paths(["/tmp/definitely-does-not-exist-014-sbom"])


class SchemaConformanceTests(unittest.TestCase):
    def test_finding_validates_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text(json.dumps(INVALID_CYCLONEDX), encoding="utf-8")
            findings = sbom_scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        errors = validate_against_schema(schema, findings[0])
        self.assertEqual(errors, [])


class ConsistencyTests(unittest.TestCase):
    def test_invalid_sbom_reference_resolves_in_the_knowledge_base(self) -> None:
        import rules

        for ref in rules.INVALID_SBOM["references"]:
            self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"cites {ref}")

    def test_vendored_schemas_are_valid_json_schema_documents(self) -> None:
        from jsonschema.validators import validator_for

        for schema_path in (sbom_validate._CYCLONEDX_SCHEMA_PATH, sbom_validate._SPDX_SCHEMA_PATH):
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            validator_cls = validator_for(schema)
            validator_cls.check_schema(schema)  # raises SchemaError if invalid


class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text(json.dumps(VALID_CYCLONEDX), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = sbom_scanner.main([str(path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), [])

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = sbom_scanner.main(["/tmp/definitely-does-not-exist-014-sbom"])
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
