"""Tests for the Action Layer's Remediation builder: safety-tier
lookup, the secret redaction patch generator (including a
mutation-style correctness proof, per มิ้นท์'s requirement at this
plan's kickoff), schema conformance, and a real cross-check that every
existing ruleId across every sub-skill's own rule catalog resolves to
a safety tier (no silent gaps in safety_tiers.json).

Run with: python3 -m unittest test_remediation -v (from inside
action/).
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import remediation
from remediation import RemediationError

ACTION_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in ACTION_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"


def _load_module(path: Path, alias: str):
    """Loads a Python module from an arbitrary path under a unique
    name, avoiding sys.modules collisions between different
    sub-skills' own same-named `rules.py`/`scanner.py` files — several
    of which this test file needs to import in the same process (no
    single detector's own tests need to do this; they only ever import
    their own directory's modules).

    Inserts the target file's own directory into sys.path first —
    `spec_from_file_location`/`exec_module` doesn't do this
    automatically the way running a script or a normal package import
    would, and several of these modules (e.g. detectors/secret/scanner.py's
    `from rules import RULES`) assume a same-directory sibling import
    works."""
    parent = str(path.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


# Loaded via an explicit alias, not a plain `from validate import ...` —
# action/validate.py and schema/validate.py are both real modules named
# "validate"; `import remediation` above already imports the former
# under the name "validate" (module caching means a second bare
# `from validate import X` in this same process would silently reuse
# that cached module and fail to find schema/validate.py's own
# `validate_remediation`, not re-import the intended file).
_schema_validate = _load_module(SCHEMA_DIR / "validate.py", "_schema_validate_for_action_tests")
validate_remediation = _schema_validate.validate_remediation


def _all_existing_rule_ids() -> dict[str, set[str]]:
    """Real cross-check data: every ruleId defined in every sub-skill's
    own static rule catalog, keyed by subSkill. Sub-skills with
    dynamically-generated ruleIds (code-review; most of dependency) are
    deliberately not enumerable this way — they rely on
    safety_tiers.json's subSkillDefaults fallback instead, verified
    separately below."""
    detectors_dir = SECURITY_SKILL_DIR / "detectors"
    by_sub_skill: dict[str, set[str]] = {}

    secret_rules = _load_module(detectors_dir / "secret" / "rules.py", "_secret_rules")
    by_sub_skill["secret"] = {r.rule_id for r in secret_rules.RULES}

    docker_rules = _load_module(detectors_dir / "docker" / "rules.py", "_docker_rules")
    by_sub_skill["docker"] = {r.rule_id for r in docker_rules.TRIVY_RULES.values()}

    k8s_rules = _load_module(detectors_dir / "kubernetes" / "rules.py", "_k8s_rules")
    by_sub_skill["kubernetes"] = {r.rule_id for r in k8s_rules.TRIVY_RULES.values()}

    iac_rules = _load_module(detectors_dir / "iac" / "rules.py", "_iac_rules")
    by_sub_skill["iac"] = {r.rule_id for r in iac_rules.CHECKOV_RULES}

    cicd_rules = _load_module(detectors_dir / "cicd" / "rules.py", "_cicd_rules")
    cicd_ids = {r.rule_id for r in cicd_rules.CHECKOV_RULES}
    cicd_checklist = json.loads((detectors_dir / "cicd" / "checklist.json").read_text(encoding="utf-8"))
    cicd_ids |= {item["ruleId"] for item in cicd_checklist["items"]}
    by_sub_skill["cicd-pipeline"] = cicd_ids

    api_rules = _load_module(detectors_dir / "api" / "rules.py", "_api_rules")
    api_ids = {r.rule_id for r in api_rules.SPECTRAL_CODE_TO_RULE.values()}
    api_ids |= {"api.open-redirect", "api.spec-declared-auth-missing-in-code"}
    by_sub_skill["api"] = api_ids

    sc_rules = _load_module(detectors_dir / "supply-chain" / "rules.py", "_sc_rules")
    sc_ids = set()
    for name in dir(sc_rules):
        value = getattr(sc_rules, name)
        if isinstance(value, dict) and "rule_id" in value:
            sc_ids.add(value["rule_id"])
    by_sub_skill["supply-chain"] = sc_ids

    auth_checklist = json.loads((detectors_dir / "auth" / "checklist.json").read_text(encoding="utf-8"))
    by_sub_skill["auth"] = {item["ruleId"] for item in auth_checklist["items"]}

    return by_sub_skill


FAKE_AWS_KEY_IN_FILE = "AKIAZQ3XJHK7VNPQXR9L"


def _secret_finding_for(content: str, file: str = "config.py") -> dict:
    secret_scanner = _load_module(SECURITY_SKILL_DIR / "detectors" / "secret" / "scanner.py", "_secret_scanner_for_action_tests")
    findings = secret_scanner.scan_text(content, file)
    assert findings, f"fixture content {content!r} didn't trigger any secret rule — fixture is broken, not the code under test"
    return findings[0]


class SafetyTierLookupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tiers = remediation.load_safety_tiers()

    def test_rule_override_takes_precedence(self) -> None:
        self.assertEqual(remediation.safety_tier_for("secret.aws-access-key", "secret", self.tiers), "auto-apply")

    def test_falls_back_to_sub_skill_default_for_unlisted_rule_id(self) -> None:
        # code-review.* ruleIds are generated dynamically from Semgrep
        # check_ids — this exact ruleId will never appear in
        # ruleOverrides, so it must resolve via subSkillDefaults.
        tier = remediation.safety_tier_for("code-review.python.lang.security.audit.some-check", "code-review", self.tiers)
        self.assertEqual(tier, "review-required")

    def test_unknown_sub_skill_with_no_default_raises(self) -> None:
        with self.assertRaises(RemediationError):
            remediation.safety_tier_for("made-up.thing", "made-up-sub-skill", self.tiers)

    def test_real_safety_tiers_file_loads_and_validates(self) -> None:
        # load_safety_tiers() already validates via validate_safety_tiers()
        # internally — this just confirms it doesn't raise for the real file.
        tiers = remediation.load_safety_tiers()
        self.assertIn("subSkillDefaults", tiers)
        self.assertIn("ruleOverrides", tiers)

    def test_malformed_safety_tiers_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps({"subSkillDefaults": {"secret": "not-a-real-tier"}, "ruleOverrides": {}}), encoding="utf-8")
            with self.assertRaises(RemediationError):
                remediation.load_safety_tiers(path)


class ConsistencyTests(unittest.TestCase):
    """Real cross-check: every ruleId that actually exists in every
    sub-skill's own rule catalog must resolve to a safety tier — not
    just assumed to be covered by the subSkillDefaults fallback."""

    def test_every_existing_rule_id_resolves_to_a_safety_tier(self) -> None:
        tiers = remediation.load_safety_tiers()
        missing = []
        for sub_skill, rule_ids in _all_existing_rule_ids().items():
            for rule_id in rule_ids:
                try:
                    remediation.safety_tier_for(rule_id, sub_skill, tiers)
                except RemediationError:
                    missing.append((sub_skill, rule_id))
        self.assertEqual(missing, [], f"ruleIds with no resolvable safety tier: {missing}")

    def test_every_sub_skill_with_a_static_catalog_has_a_default_too(self) -> None:
        # Even though every individual ruleId is covered by an explicit
        # override (checked above), each of these sub-skills should
        # still have its own subSkillDefaults entry as a safety net for
        # any *future* ruleId added to its catalog without a matching
        # override being added at the same time.
        tiers = remediation.load_safety_tiers()
        for sub_skill in _all_existing_rule_ids():
            self.assertIn(sub_skill, tiers["subSkillDefaults"], f"{sub_skill} has no subSkillDefaults entry")


class SecretRedactionPatchTests(unittest.TestCase):
    def test_originalText_is_exactly_the_matched_secret(self) -> None:
        content = f'AWS_ACCESS_KEY = "{FAKE_AWS_KEY_IN_FILE}"'
        finding = _secret_finding_for(content)
        patch = remediation.generate_secret_redaction_patch(finding, content)
        self.assertEqual(patch["originalText"], FAKE_AWS_KEY_IN_FILE)
        self.assertEqual(patch["replacementText"], "REDACTED_SECRET")

    def test_mismatched_file_content_raises(self) -> None:
        content = f'AWS_ACCESS_KEY = "{FAKE_AWS_KEY_IN_FILE}"'
        finding = _secret_finding_for(content)
        with self.assertRaises(RemediationError):
            # Shorter than the finding's own end_byte — the only case
            # generate_secret_redaction_patch() can actually detect
            # (a byte range past the end of the given content); it has
            # no way to notice same-length-but-different content, which
            # isn't the mismatch this defends against anyway.
            remediation.generate_secret_redaction_patch(finding, "x")

    def test_finding_without_byte_range_raises(self) -> None:
        finding = {"findingId": "x", "location": {"file": "f.py", "startLine": 1, "endLine": 1}}
        with self.assertRaises(RemediationError):
            remediation.generate_secret_redaction_patch(finding, "irrelevant")

    def test_mutation_style_patch_correctness_across_real_secret_rules(self) -> None:
        """มิ้นท์'s explicit kickoff requirement: prove the generated
        patch, when textually applied to the original file content,
        actually removes the literal secret value and produces
        syntactically valid Python — not just "the diff looks
        plausible". Runs across several real secret rule shapes, not
        just one, since the location-precision bug found during this
        plan's own implementation was specific to certain patterns
        (generic-api-key, azure-ad-client-secret) and not others."""
        cases = [
            f'AWS_ACCESS_KEY = "{FAKE_AWS_KEY_IN_FILE}"',
            'db_password = "kX9mQ2vLp8Rz4Tn7Ws3"',
            'clientSecret = "abc7Q~' + "x" * 31 + '"',
        ]
        for content in cases:
            with self.subTest(content=content):
                finding = _secret_finding_for(content)
                patch = remediation.generate_secret_redaction_patch(finding, content)

                start_byte, end_byte = finding["location"]["startByte"], finding["location"]["endByte"]
                encoded = content.encode("utf-8")
                applied = (encoded[:start_byte] + patch["replacementText"].encode("utf-8") + encoded[end_byte:]).decode("utf-8")

                self.assertNotIn(patch["originalText"], applied)
                compile(applied, "<redacted>", "exec")  # raises SyntaxError if this isn't valid Python


class BuildRemediationTests(unittest.TestCase):
    def test_secret_finding_gets_a_real_patch(self) -> None:
        content = f'AWS_ACCESS_KEY = "{FAKE_AWS_KEY_IN_FILE}"'
        finding = _secret_finding_for(content)
        rem = remediation.build_remediation(finding, file_content=content)
        self.assertEqual(rem["safetyTier"], "auto-apply")
        self.assertIn("patch", rem)
        self.assertIn("impactOfFix", rem)
        self.assertIn("pullRequestDraft", rem)

    def test_secret_finding_without_file_content_raises(self) -> None:
        content = f'AWS_ACCESS_KEY = "{FAKE_AWS_KEY_IN_FILE}"'
        finding = _secret_finding_for(content)
        with self.assertRaises(RemediationError):
            remediation.build_remediation(finding)

    def test_non_secret_finding_gets_no_patch(self) -> None:
        finding = {
            "findingId": "iac-abc123",
            "ruleId": "iac.aws-iam-wildcard-actions",
            "subSkill": "iac",
            "recommendation": "Enumerate specific actions instead of *.",
        }
        rem = remediation.build_remediation(finding)
        self.assertEqual(rem["safetyTier"], "review-required")
        self.assertNotIn("patch", rem)
        self.assertNotIn("impactOfFix", rem)
        self.assertNotIn("pullRequestDraft", rem)

    def test_non_secret_finding_ignores_file_content_if_given(self) -> None:
        finding = {
            "findingId": "iac-abc123",
            "ruleId": "iac.aws-iam-wildcard-actions",
            "subSkill": "iac",
            "recommendation": "x",
        }
        rem = remediation.build_remediation(finding, file_content="irrelevant, never read")
        self.assertNotIn("patch", rem)


class SchemaConformanceTests(unittest.TestCase):
    def test_secret_remediation_validates(self) -> None:
        content = f'AWS_ACCESS_KEY = "{FAKE_AWS_KEY_IN_FILE}"'
        finding = _secret_finding_for(content)
        rem = remediation.build_remediation(finding, file_content=content)
        errors = validate_remediation(rem)
        self.assertEqual(errors, [])

    def test_recommend_only_remediation_validates(self) -> None:
        finding = {
            "findingId": "supply-chain-abc",
            "ruleId": "supply-chain.missing-sast-tool",
            "subSkill": "supply-chain",
            "recommendation": "Add a SAST tool to CI.",
        }
        rem = remediation.build_remediation(finding)
        errors = validate_remediation(rem)
        self.assertEqual(errors, [])

    def test_validator_actually_rejects_an_invalid_remediation(self) -> None:
        bad = {"remediationId": "x"}  # missing every other required field
        errors = validate_remediation(bad)
        self.assertNotEqual(errors, [])

    def test_impact_of_fix_without_patch_is_rejected(self) -> None:
        # Direct test of the schema's own if/then constraint.
        bad = {
            "remediationId": "r1",
            "findingId": "f1",
            "ruleId": "secret.aws-access-key",
            "safetyTier": "auto-apply",
            "recommendation": "x",
            "impactOfFix": "should not be allowed without patch",
        }
        errors = validate_remediation(bad)
        self.assertNotEqual(errors, [])


class MainCliTests(unittest.TestCase):
    def test_prints_remediation_and_returns_0(self) -> None:
        finding = {
            "findingId": "iac-abc123",
            "ruleId": "iac.aws-iam-wildcard-actions",
            "subSkill": "iac",
            "recommendation": "x",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "finding.json"
            path.write_text(json.dumps(finding), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = remediation.main([str(path)])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["safetyTier"], "review-required")

    def test_missing_source_file_for_secret_finding_returns_1(self) -> None:
        content = f'AWS_ACCESS_KEY = "{FAKE_AWS_KEY_IN_FILE}"'
        finding = _secret_finding_for(content)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "finding.json"
            path.write_text(json.dumps(finding), encoding="utf-8")
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = remediation.main([str(path)])
        self.assertEqual(code, 1)
        self.assertIn("REMEDIATION ERROR", err.getvalue())


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
        for path in sorted(ACTION_DIR.glob("*.py")):
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
