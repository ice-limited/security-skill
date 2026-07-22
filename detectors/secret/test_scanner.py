"""Tests for the secret detector: pattern matches, entropy filtering,
byte-offset precision, findingId stability, and schema conformance.

None of the values below are real secrets — they're synthetic fixtures
constructed to match each rule's regex shape.

Run with: python3 -m unittest test_scanner -v (from inside
detectors/secret/).
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import scanner
from rules import RULES

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = DETECTOR_DIR.parent.parent
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"
KNOWLEDGE_DIR = SECURITY_SKILL_DIR / "knowledge"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(KNOWLEDGE_DIR))
import standards  # noqa: E402

# Synthetic fixtures — shaped to match each rule's regex, not real secrets.
FAKE_AWS_KEY = "AKIA" + "FAKE" * 4  # AKIA + 16 [A-Z2-7] chars
FAKE_GITHUB_PAT = "ghp_" + "x" * 36
FAKE_GITLAB_PAT = "glpat-" + "x" * 20
FAKE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakesignaturepart123456"
FAKE_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD91JkC/6DHhAOWiaBIKAKp9y6VeYtNgqZKfakefake\n"
    "-----END RSA PRIVATE KEY-----"
)
FAKE_GCP_KEY = "AIza" + "F" * 35
FAKE_AZURE_SECRET = "abc7Q~" + "x" * 31
FAKE_HIGH_ENTROPY_GENERIC = "kX9mQ2vLp8Rz4Tn7Ws3"
FAKE_LOW_ENTROPY_GENERIC = "1111111111"


def _rule_ids() -> list[str]:
    return [r.rule_id for r in RULES]


class PerRuleDetectionTests(unittest.TestCase):
    def test_finds_aws_access_key(self) -> None:
        findings = scanner.scan_text(f'key = "{FAKE_AWS_KEY}"', "config.env")
        self.assertTrue(any(f["ruleId"] == "secret.aws-access-key" for f in findings))

    def test_finds_github_pat(self) -> None:
        findings = scanner.scan_text(f"token: {FAKE_GITHUB_PAT}", "ci.yml")
        self.assertTrue(any(f["ruleId"] == "secret.github-pat" for f in findings))

    def test_finds_gitlab_pat(self) -> None:
        findings = scanner.scan_text(f"token: {FAKE_GITLAB_PAT}", "ci.yml")
        self.assertTrue(any(f["ruleId"] == "secret.gitlab-pat" for f in findings))

    def test_finds_jwt(self) -> None:
        findings = scanner.scan_text(f"auth_token = '{FAKE_JWT}'", "app.py")
        self.assertTrue(any(f["ruleId"] == "secret.jwt" for f in findings))

    def test_finds_private_key(self) -> None:
        findings = scanner.scan_text(FAKE_PRIVATE_KEY, "id_rsa")
        self.assertTrue(any(f["ruleId"] == "secret.private-key" for f in findings))

    def test_finds_gcp_api_key(self) -> None:
        findings = scanner.scan_text(f'apiKey: "{FAKE_GCP_KEY}"', "config.yaml")
        self.assertTrue(any(f["ruleId"] == "secret.gcp-api-key" for f in findings))

    def test_finds_azure_ad_client_secret(self) -> None:
        findings = scanner.scan_text(f'clientSecret = "{FAKE_AZURE_SECRET}"', "settings.py")
        self.assertTrue(any(f["ruleId"] == "secret.azure-ad-client-secret" for f in findings))

    def test_finds_generic_high_entropy_credential(self) -> None:
        findings = scanner.scan_text(f'db_password = "{FAKE_HIGH_ENTROPY_GENERIC}"', "settings.py")
        self.assertTrue(any(f["ruleId"] == "secret.generic-api-key" for f in findings))


class FalsePositiveTests(unittest.TestCase):
    def test_known_placeholder_is_not_flagged(self) -> None:
        findings = scanner.scan_text('key = "AKIAIOSFODNN7EXAMPLE"', "README.md")
        self.assertFalse(any(f["ruleId"] == "secret.aws-access-key" for f in findings))

    def test_low_entropy_generic_match_is_not_flagged(self) -> None:
        findings = scanner.scan_text(f'password = "{FAKE_LOW_ENTROPY_GENERIC}"', "settings.py")
        self.assertFalse(any(f["ruleId"] == "secret.generic-api-key" for f in findings))

    def test_clean_file_produces_no_findings(self) -> None:
        content = "def add(a, b):\n    return a + b\n"
        self.assertEqual(scanner.scan_text(content, "math.py"), [])

    def test_empty_content_produces_no_findings(self) -> None:
        self.assertEqual(scanner.scan_text("", "empty.py"), [])


class OverlapSuppressionTests(unittest.TestCase):
    # A higher-entropy AWS-key-shaped value (unlike FAKE_AWS_KEY, whose
    # low character diversity happens to sit under the generic rule's
    # entropy gate) assigned to a "key"-suggestive variable name — this
    # exact fixture is what exposed a real duplicate-finding bug while
    # testing plan 006: secret.aws-access-key and secret.generic-api-key
    # both fired on the same underlying secret.
    HIGH_ENTROPY_AWS_KEY = "AKIA2QX7ZM4NPLW3RJ6T"

    def test_specific_rule_match_suppresses_overlapping_generic_match(self) -> None:
        self.assertGreaterEqual(scanner._shannon_entropy(self.HIGH_ENTROPY_AWS_KEY), scanner._MIN_ENTROPY_BITS_PER_CHAR)
        content = f'aws_key = "{self.HIGH_ENTROPY_AWS_KEY}"'
        findings = scanner.scan_text(content, "config.env")
        rule_ids = [f["ruleId"] for f in findings]
        self.assertIn("secret.aws-access-key", rule_ids)
        self.assertNotIn("secret.generic-api-key", rule_ids)
        self.assertEqual(len(findings), 1, f"expected only the specific-rule finding, got {rule_ids}")

    def test_non_overlapping_generic_match_is_not_suppressed(self) -> None:
        # A generic match far away from any specific-rule match (no
        # byte-range overlap) must still be reported — the suppression
        # is scoped to actual overlap, not "any specific match exists
        # anywhere in the file."
        content = f'aws_key = "{self.HIGH_ENTROPY_AWS_KEY}"\npassword = "{FAKE_HIGH_ENTROPY_GENERIC}"'
        findings = scanner.scan_text(content, "config.env")
        rule_ids = [f["ruleId"] for f in findings]
        self.assertIn("secret.aws-access-key", rule_ids)
        self.assertIn("secret.generic-api-key", rule_ids)


class EntropyTests(unittest.TestCase):
    def test_repeated_character_has_zero_entropy(self) -> None:
        self.assertEqual(scanner._shannon_entropy("aaaaaaaa"), 0.0)

    def test_diverse_string_has_higher_entropy_than_repeated(self) -> None:
        self.assertGreater(scanner._shannon_entropy(FAKE_HIGH_ENTROPY_GENERIC), scanner._shannon_entropy("aaaaaaaa"))

    def test_empty_string_has_zero_entropy(self) -> None:
        self.assertEqual(scanner._shannon_entropy(""), 0.0)

    def test_looks_random_requires_both_length_and_entropy(self) -> None:
        # High entropy but too short — must not pass.
        self.assertFalse(scanner._looks_random("aB3!"))
        # Long but low entropy — must not pass.
        self.assertFalse(scanner._looks_random("a" * 20))
        # Long and high entropy — must pass.
        self.assertTrue(scanner._looks_random(FAKE_HIGH_ENTROPY_GENERIC))


class LocationPrecisionTests(unittest.TestCase):
    def test_byte_offset_accounts_for_multibyte_utf8_before_match(self) -> None:
        # "—" (em dash) is 3 bytes in UTF-8 but 1 character — a
        # char-offset-only implementation would under-report the byte
        # position of anything after it. Deliberately tested, per the
        # kickoff's byte-vs-char-offset decision.
        prefix = "# note: em dash — here\n"
        content = prefix + f'key = "{FAKE_AWS_KEY}"'
        findings = scanner.scan_text(content, "config.env")
        aws_finding = next(f for f in findings if f["ruleId"] == "secret.aws-access-key")
        char_offset_of_match = content.index(FAKE_AWS_KEY)
        true_byte_offset = len(content[:char_offset_of_match].encode("utf-8"))
        self.assertEqual(aws_finding["location"]["startByte"], true_byte_offset)
        # The whole point: byte offset must differ from char offset here.
        self.assertNotEqual(true_byte_offset, char_offset_of_match)

    def test_line_numbers_are_one_indexed_and_correct(self) -> None:
        content = "line one\nline two\nkey = \"" + FAKE_AWS_KEY + '"\n'
        findings = scanner.scan_text(content, "config.env")
        aws_finding = next(f for f in findings if f["ruleId"] == "secret.aws-access-key")
        self.assertEqual(aws_finding["location"]["startLine"], 3)


class FindingIdTests(unittest.TestCase):
    def test_deterministic_for_identical_input(self) -> None:
        content = f'key = "{FAKE_AWS_KEY}"'
        first = scanner.scan_text(content, "config.env")
        second = scanner.scan_text(content, "config.env")
        self.assertEqual(first[0]["findingId"], second[0]["findingId"])

    def test_distinct_findings_on_same_line_get_distinct_ids(self) -> None:
        # Different rules on the same line were never actually
        # ambiguous (ruleId alone already distinguishes them) — the
        # real risk plan 004 found is *two matches of the same rule* on
        # one line (e.g. two different AWS keys side by side), which is
        # what this specifically exercises.
        second_aws_key = "AKIA" + "TEST" * 4
        self.assertNotEqual(FAKE_AWS_KEY, second_aws_key)
        content = f'a = "{FAKE_AWS_KEY}"; b = "{second_aws_key}"'
        findings = [f for f in scanner.scan_text(content, "config.env") if f["ruleId"] == "secret.aws-access-key"]
        self.assertEqual(len(findings), 2, "expected both AWS keys to be found")
        ids = [f["findingId"] for f in findings]
        self.assertEqual(len(ids), len(set(ids)), "findingIds must be unique per distinct match of the same rule")

    def test_distinct_findings_of_different_rules_on_same_line_also_get_distinct_ids(self) -> None:
        content = f'a = "{FAKE_AWS_KEY}"; b = "{FAKE_GCP_KEY}"'
        findings = scanner.scan_text(content, "config.env")
        ids = [f["findingId"] for f in findings]
        self.assertEqual(len(ids), len(set(ids)))


class SeverityTests(unittest.TestCase):
    def test_every_finding_is_critical_regardless_of_confidence(self) -> None:
        content = "\n".join(
            [
                f'aws = "{FAKE_AWS_KEY}"',
                f'db_password = "{FAKE_HIGH_ENTROPY_GENERIC}"',
            ]
        )
        findings = scanner.scan_text(content, "config.env")
        self.assertTrue(findings)
        self.assertTrue(all(f["severity"] == "Critical" for f in findings))
        # Confidence still varies even though severity doesn't.
        confidences = {f["confidence"] for f in findings}
        self.assertGreater(len(confidences), 1)


class ScanFileTests(unittest.TestCase):
    def test_reads_content_from_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.env"
            path.write_text(f'key = "{FAKE_AWS_KEY}"', encoding="utf-8")
            findings = scanner.scan_file(path)
            self.assertTrue(any(f["ruleId"] == "secret.aws-access-key" for f in findings))
            self.assertEqual(findings[0]["location"]["file"], str(path))

    def test_artifact_type_is_passed_through(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text(f'ENV KEY="{FAKE_AWS_KEY}"', encoding="utf-8")
            findings = scanner.scan_file(path, artifact_type="dockerfile")
            self.assertEqual(findings[0]["artifactType"], "dockerfile")


class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.env"
            path.write_text(f'key = "{FAKE_AWS_KEY}"', encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([str(path)])
            self.assertEqual(code, 0)
            parsed = json.loads(out.getvalue())
            self.assertTrue(any(f["ruleId"] == "secret.aws-access-key" for f in parsed))


class SchemaConformanceTests(unittest.TestCase):
    """Every finding this detector emits must actually validate against
    finding.schema.json — not just "look right" by inspection."""

    def test_every_rule_type_produces_a_schema_valid_finding(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        fixtures = {
            "secret.aws-access-key": f'key = "{FAKE_AWS_KEY}"',
            "secret.github-pat": f"token: {FAKE_GITHUB_PAT}",
            "secret.gitlab-pat": f"token: {FAKE_GITLAB_PAT}",
            "secret.jwt": f"auth = '{FAKE_JWT}'",
            "secret.private-key": FAKE_PRIVATE_KEY,
            "secret.gcp-api-key": f'apiKey: "{FAKE_GCP_KEY}"',
            "secret.azure-ad-client-secret": f'clientSecret = "{FAKE_AZURE_SECRET}"',
            "secret.generic-api-key": f'db_password = "{FAKE_HIGH_ENTROPY_GENERIC}"',
        }
        self.assertEqual(set(fixtures), set(_rule_ids()), "every rule needs a fixture in this test")
        for rule_id, content in fixtures.items():
            findings = [f for f in scanner.scan_text(content, "fixture.txt") if f["ruleId"] == rule_id]
            self.assertTrue(findings, f"no finding produced for {rule_id}")
            errors = validate_against_schema(schema, findings[0])
            self.assertEqual(errors, [], f"{rule_id} finding is not schema-valid: {errors}")


class ConsistencyTests(unittest.TestCase):
    """Nothing else would catch a rule citing a standard ID that doesn't
    actually exist in the knowledge base — same pattern as plans
    002/003/004's cross-repo consistency checks."""

    def test_every_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        for rule in RULES:
            for ref in rule.references:
                self.assertTrue(
                    standards.exists(ref["standard"], ref["id"]),
                    f"{rule.rule_id} cites {ref['standard']} {ref['id']}, not found in knowledge base",
                )

    def test_every_rule_id_matches_naming_convention(self) -> None:
        import re

        pattern = re.compile(r"^secret\.[a-z0-9-]+(\.[a-z0-9-]+)*$")
        for rule in RULES:
            self.assertTrue(pattern.match(rule.rule_id), f"{rule.rule_id} doesn't match the ruleId convention")

    def test_no_duplicate_rule_ids(self) -> None:
        ids = _rule_ids()
        self.assertEqual(len(ids), len(set(ids)))


class CrossPlatformEncodingTests(unittest.TestCase):
    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


class SourceEncodingAuditTests(unittest.TestCase):
    """Static-analysis regression guard — see schema/test_renderers.py's
    class of the same name. Scans every .py file in this directory."""

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
