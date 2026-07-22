"""Tests for the knowledge base loader, semantic reference validation, and
internal referential integrity of the vendored standards data.

Run with: python3 -m unittest test_knowledge -v (from inside knowledge/).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import standards
from validate_references import find_unknown_references

KNOWLEDGE_DIR = Path(__file__).parent
SCHEMA_DIR = KNOWLEDGE_DIR.parent / "schema"
SAMPLE_REPORT = SCHEMA_DIR / "testdata" / "sample-report.json"


class LoaderTests(unittest.TestCase):
    def test_every_standard_file_loads_and_entries_have_titles(self) -> None:
        for std in standards.known_standards():
            entries = standards.load(std)
            for entry_id, entry in entries.items():
                self.assertIn(
                    "title", entry, f"{std} entry {entry_id} is missing a title"
                )

    def test_metadata_keys_are_excluded_from_entries(self) -> None:
        entries = standards.load("OWASP-Top10")
        self.assertNotIn("_note", entries)
        self.assertNotIn("_edition", entries)

    def test_unknown_id_returns_none_and_false(self) -> None:
        self.assertFalse(standards.exists("CWE", "CWE-999999"))
        self.assertIsNone(standards.get("CWE", "CWE-999999"))
        self.assertIsNone(standards.title("CWE", "CWE-999999"))
        self.assertIsNone(standards.url("CWE", "CWE-999999"))

    def test_unknown_standard_raises(self) -> None:
        with self.assertRaises(standards.UnknownStandardError):
            standards.load("NOT-A-REAL-STANDARD")

    def test_cwe_url_is_derived_from_template(self) -> None:
        self.assertEqual(
            standards.url("CWE", "CWE-89"),
            "https://cwe.mitre.org/data/definitions/89.html",
        )

    def test_capec_url_is_derived_from_template(self) -> None:
        self.assertEqual(
            standards.url("CAPEC", "CAPEC-66"),
            "https://capec.mitre.org/data/definitions/66.html",
        )

    def test_owasp_entries_have_explicit_url_not_derived(self) -> None:
        # OWASP standards have no numeric-suffix URL template — every
        # entry must carry its own explicit "url".
        for entry_id, entry in standards.load("OWASP-Top10").items():
            self.assertIn("url", entry, f"OWASP-Top10 {entry_id} has no url")

    def test_cert_secure_coding_loads_empty_without_error(self) -> None:
        # Intentionally empty (see the file's own "_note") — must load
        # as an empty dict, not raise or return the metadata key itself.
        self.assertEqual(standards.load("CERT-Secure-Coding"), {})

    def test_title_and_url_work_for_non_cwe_capec_standards(self) -> None:
        # The earlier url()/title() tests only exercised CWE/CAPEC
        # (template-derived URLs). Explicit-URL standards go through a
        # different branch in standards.url() and need their own check.
        self.assertEqual(standards.title("OWASP-Top10", "A05:2025"), "Injection")
        self.assertEqual(
            standards.url("OWASP-Top10", "A05:2025"),
            "https://owasp.org/Top10/2025/A05_2025-Injection/",
        )
        self.assertEqual(standards.title("NIST-SSDF", "PW"), "Produce Well-Secured Software")

    def test_every_entry_url_is_https(self) -> None:
        for std in standards.known_standards():
            for entry_id in standards.load(std):
                entry_url = standards.url(std, entry_id)
                self.assertIsNotNone(entry_url, f"{std} {entry_id} has no resolvable url")
                self.assertTrue(
                    entry_url.startswith("https://"),
                    f"{std} {entry_id} url is not https: {entry_url}",
                )


class CrossRepoConsistencyTests(unittest.TestCase):
    """The knowledge base and the finding schema (a sibling directory,
    plan 001) must agree on which `standard` values are valid — nothing
    else enforces that the two don't quietly drift apart."""

    def test_schema_standard_enum_matches_knowledge_base(self) -> None:
        finding_schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text())
        schema_enum = set(
            finding_schema["$defs"]["standardReference"]["properties"]["standard"]["enum"]
        )
        self.assertEqual(schema_enum, set(standards.known_standards()))


class ReferentialIntegrityTests(unittest.TestCase):
    """Cross-checks between standards must point at real entries in this
    repo's own data, not just plausible-looking IDs."""

    def test_capec_related_cwe_ids_exist_in_cwe_json(self) -> None:
        for capec_id, entry in standards.load("CAPEC").items():
            for cwe_id in entry.get("relatedCwe", []):
                self.assertTrue(
                    standards.exists("CWE", cwe_id),
                    f"{capec_id} cites {cwe_id}, which is not in cwe.json",
                )

    def test_owasp_top10_related_cwe_ids_exist_in_cwe_json(self) -> None:
        for category_id, entry in standards.load("OWASP-Top10").items():
            for cwe_id in entry.get("relatedCwe", []):
                self.assertTrue(
                    standards.exists("CWE", cwe_id),
                    f"{category_id} cites {cwe_id}, which is not in cwe.json",
                )


class ReferenceValidationTests(unittest.TestCase):
    def test_sample_report_references_all_resolve(self) -> None:
        report = json.loads(SAMPLE_REPORT.read_text())
        problems = find_unknown_references(report)
        self.assertEqual(problems, [])

    def test_stale_2021_edition_reference_is_flagged(self) -> None:
        # Regression guard for exactly the bug plan 002 found and fixed in
        # plan 001's fixture: an old-edition ID must NOT silently pass.
        report = json.loads(SAMPLE_REPORT.read_text())
        report["findings"][0]["references"].append(
            {"standard": "OWASP-Top10", "id": "A03:2021"}
        )
        problems = find_unknown_references(report)
        self.assertEqual(len(problems), 1)
        self.assertIn("A03:2021", problems[0])

    def test_typo_d_cwe_id_is_flagged(self) -> None:
        report = json.loads(SAMPLE_REPORT.read_text())
        report["findings"][0]["references"].append({"standard": "CWE", "id": "CWE-89999"})
        problems = find_unknown_references(report)
        self.assertEqual(len(problems), 1)
        self.assertIn("CWE-89999", problems[0])

    def test_report_with_no_findings_has_no_problems(self) -> None:
        report = {"findings": []}
        self.assertEqual(find_unknown_references(report), [])

    def test_finding_with_no_references_is_fine(self) -> None:
        report = {"findings": [{"findingId": "f-x", "references": []}]}
        self.assertEqual(find_unknown_references(report), [])


if __name__ == "__main__":
    unittest.main()
