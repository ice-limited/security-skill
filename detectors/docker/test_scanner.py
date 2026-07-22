"""Tests for the Docker detector: real Trivy subprocess calls (not
mocked — see plans/009-docker-skill.md's kickoff note on why), custom
pattern-rule scanning, result-to-finding mapping, schema conformance,
and error handling.

Requires the real `trivy` CLI on PATH and network access for its first
run (checks bundle). Run with: python3 -m unittest test_scanner -v
(from inside detectors/docker/).
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
from scanner import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402


def _trivy_available() -> bool:
    return shutil.which("trivy") is not None


# Deliberately obvious/synthetic Dockerfiles, not real-world content —
# enough for Trivy + this module's custom rules to actually fire, not
# just "look" vulnerable.
VULNERABLE_DOCKERFILE = """FROM ubuntu:latest

RUN apt-get update && \\
    apt-get upgrade -y

RUN curl -sSL https://get.example.com/install.sh \\
    | bash -s --

ADD config.json /app/config.json

USER root
"""

CLEAN_DOCKERFILE = """FROM ubuntu:22.04

RUN groupadd -r appuser && useradd -r -g appuser appuser
COPY entrypoint.sh /app/entrypoint.sh
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
USER appuser
CMD ["/app/entrypoint.sh"]
"""

# Real npm lockfile-style secret-in-ENV pattern that would trip Trivy's
# own DS-0031 if it weren't excluded — verifies the exclusion from
# *within* the test suite, not just interactively (per the kickoff's
# QA flag).
SECRET_IN_ENV_DOCKERFILE = """FROM ubuntu:22.04
ENV API_KEY=sk_live_abcdefghijklmnopqrstuvwxyz123456
USER nobody
"""

ADD_LEGITIMATE_USES_DOCKERFILE = """FROM ubuntu:22.04
ADD app.tar.gz /app
ADD https://example.com/file.txt /app/file.txt
USER nobody
"""

# A real, common pattern (build stage + final stage) — verifies
# unpinned-base-image/root-user only fire against the *final* stage,
# not an intermediate builder stage that happens to be pinned.
MULTISTAGE_DOCKERFILE = """FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
RUN go build -o app .

FROM ubuntu:latest
COPY --from=builder /src/app /app/app
USER root
CMD ["/app/app"]
"""

# Deliberately a *different* single finding from VULNERABLE_DOCKERFILE
# (only unpinned-base-image, none of the others) so a multi-directory
# scan test can positively confirm both directories were actually
# scanned, rather than one happening to be clean (which wouldn't
# distinguish "scanned but clean" from "never scanned at all").
DIFFERENTLY_VULNERABLE_DOCKERFILE = """FROM alpine:latest

RUN adduser -D appuser
USER appuser
HEALTHCHECK CMD true
"""


class PerRuleDetectionTests(unittest.TestCase):
    def _write(self, tmp: str, content: str, name: str = "Dockerfile") -> Path:
        path = Path(tmp) / name
        path.write_text(content, encoding="utf-8")
        return path

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_finds_all_trivy_and_custom_rules_in_one_dockerfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, VULNERABLE_DOCKERFILE)
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(
            rule_ids,
            {
                "docker.unpinned-base-image",
                "docker.root-user",
                "docker.missing-healthcheck",
                "docker.apt-upgrade",
                "docker.curl-pipe-shell",
                "docker.add-instead-of-copy",
            },
            rule_ids,
        )
        for f in findings:
            self.assertEqual(f["subSkill"], "docker")
            self.assertEqual(f["artifactType"], "dockerfile")

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_clean_dockerfile_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, CLEAN_DOCKERFILE)
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [])

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_trivys_own_secret_check_is_excluded_not_supplemented(self) -> None:
        # Verifies the DS-0031 exclusion from within the test suite,
        # not just interactively — 006 owns secrets-in-ENV exclusively.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, SECRET_IN_ENV_DOCKERFILE)
            findings = scanner.scan_paths([tmp])
        self.assertFalse(any("secret" in f["ruleId"] for f in findings), findings)

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_trivys_own_secret_check_is_excluded_for_build_args_too(self) -> None:
        # Completes the DS-0031 verification (per the "test plan 009"
        # round): the ENV form was already covered above, but DS-0031
        # also fires on ARG (build-args) — confirmed excluded there too.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "FROM ubuntu:22.04\nARG API_KEY=sk_live_abcdefghijklmnopqrstuvwxyz123456\nUSER nobody\n")
            findings = scanner.scan_paths([tmp])
        self.assertFalse(any("secret" in f["ruleId"] for f in findings), findings)

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_multistage_dockerfile_only_flags_the_final_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, MULTISTAGE_DOCKERFILE)
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(rule_ids, {"docker.unpinned-base-image", "docker.root-user", "docker.missing-healthcheck"})

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_add_with_archive_or_url_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, ADD_LEGITIMATE_USES_DOCKERFILE)
            (Path(tmp) / "app.tar.gz").write_text("fake archive contents", encoding="utf-8")
            findings = scanner.scan_paths([tmp])
        self.assertFalse(any(f["ruleId"] == "docker.add-instead-of-copy" for f in findings), findings)

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_scanning_two_separate_directories_aggregates_findings_from_both(self) -> None:
        # Regression test: trivy config rejects more than one target
        # per invocation ("multiple targets cannot be specified") —
        # scan_paths() must invoke it once per path and aggregate, not
        # try to pass the whole list through in one call. Uses two
        # *distinctly* vulnerable fixtures (not one vulnerable + one
        # clean) so the assertion can't be satisfied by silently
        # skipping one directory — caught a real test-quality gap this
        # way during mutation testing (an earlier version paired with
        # a clean second directory, which didn't distinguish "scanned
        # but clean" from "never scanned").
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            self._write(tmp_a, VULNERABLE_DOCKERFILE)
            self._write(tmp_b, DIFFERENTLY_VULNERABLE_DOCKERFILE)
            findings = scanner.scan_paths([tmp_a, tmp_b])
        rule_ids_a = {f["ruleId"] for f in findings if tmp_a in f["location"]["file"]}
        rule_ids_b = {f["ruleId"] for f in findings if tmp_b in f["location"]["file"]}
        self.assertIn("docker.root-user", rule_ids_a)
        self.assertEqual(rule_ids_b, {"docker.unpinned-base-image"}, rule_ids_b)


@unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
class SchemaConformanceTests(unittest.TestCase):
    def test_real_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text(VULNERABLE_DOCKERFILE, encoding="utf-8")
            findings = scanner.scan_paths([tmp])
        self.assertEqual(len(findings), 6)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


@unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
class ErrorHandlingTests(unittest.TestCase):
    def test_bad_path_raises_scanner_error(self) -> None:
        with self.assertRaises(ScannerError):
            scanner.scan_paths(["/tmp/definitely-does-not-exist-009-dockerfile"])

    def test_missing_trivy_binary_raises_actionable_error(self) -> None:
        with mock.patch("scanner.shutil.which", return_value=None):
            with self.assertRaises(ScannerError) as ctx:
                scanner.run_trivy("irrelevant")
        self.assertIn("brew install trivy", str(ctx.exception))

    def test_returncode_nonzero_raises_even_with_valid_json_stdout(self) -> None:
        # Isolates the return-code check itself (mirrors the same
        # test-quality lesson from 008: a bad path also produces empty
        # stdout, which would independently fail JSON parsing and mask
        # whether the return-code check does anything).
        fake_proc = mock.Mock(returncode=1, stdout='{"Results": []}', stderr="mocked failure")
        with mock.patch("scanner.subprocess.run", return_value=fake_proc):
            with self.assertRaises(ScannerError):
                scanner.run_trivy("irrelevant")


class MappingTests(unittest.TestCase):
    """Pure-function unit tests — no trivy subprocess needed, fast and
    deterministic."""

    def test_trivy_severity_mapping(self) -> None:
        for raw, expected in [("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")]:
            misconfig = {"ID": "DS-0001", "Severity": raw, "CauseMetadata": {"StartLine": 1, "EndLine": 1}}
            finding = scanner.map_trivy_misconfig(misconfig, "Dockerfile", "dockerfile", "0.72.0")
            self.assertEqual(finding["severity"], expected)

    def test_unknown_trivy_check_id_returns_none(self) -> None:
        # Trivy's config scan has many general checks beyond this
        # plan's declared scope — anything not in the curated catalog
        # is silently skipped, not an error.
        misconfig = {"ID": "DS-9999", "Severity": "HIGH", "CauseMetadata": {}}
        self.assertIsNone(scanner.map_trivy_misconfig(misconfig, "Dockerfile", "dockerfile", "0.72.0"))

    def test_resolve_target_path_for_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolved = scanner._resolve_target_path(tmp, "Dockerfile")
        self.assertEqual(str(resolved), str(Path(tmp) / "Dockerfile"))

    def test_resolve_target_path_for_single_file_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "Dockerfile"
            file_path.write_text("FROM scratch\n", encoding="utf-8")
            resolved = scanner._resolve_target_path(str(file_path), "Dockerfile")
        self.assertEqual(str(resolved), str(file_path))

    def test_apt_upgrade_pattern_matches_multiline_run(self) -> None:
        findings = scanner.scan_custom_rules(VULNERABLE_DOCKERFILE, "Dockerfile")
        self.assertTrue(any(f["ruleId"] == "docker.apt-upgrade" for f in findings))

    def test_curl_pipe_shell_does_not_false_positive_on_plain_download(self) -> None:
        content = "FROM ubuntu:22.04\nRUN curl -o /tmp/x.tar.gz https://example.com/x.tar.gz\n"
        findings = scanner.scan_custom_rules(content, "Dockerfile")
        self.assertFalse(any(f["ruleId"] == "docker.curl-pipe-shell" for f in findings))

    def test_custom_rules_do_not_false_positive_on_comments_mentioning_the_pattern(self) -> None:
        # Found during the "test plan 009" round, not hypothetical: a
        # comment merely *mentioning* an anti-pattern (a real, common
        # thing to write, e.g. explaining what not to do) was being
        # flagged as if the anti-pattern were actually present in a
        # real instruction.
        content = (
            "FROM ubuntu:22.04\n"
            "# Do NOT do this: curl http://example.com/install.sh | bash\n"
            "# Also avoid: apt-get upgrade\n"
            "RUN apt-get install -y curl\n"
            "USER nobody\n"
        )
        findings = scanner.scan_custom_rules(content, "Dockerfile")
        self.assertEqual(findings, [], findings)

    def test_add_in_a_comment_is_not_flagged(self) -> None:
        content = "FROM ubuntu:22.04\n# ADD foo bar\nUSER nobody\n"
        findings = scanner.scan_custom_rules(content, "Dockerfile")
        self.assertEqual(findings, [], findings)

    def test_curl_pipe_shell_does_not_false_positive_when_piped_to_non_shell(self) -> None:
        content = "FROM ubuntu:22.04\nRUN curl https://example.com/a.sh | tee /tmp/a.sh\n"
        findings = scanner.scan_custom_rules(content, "Dockerfile")
        self.assertFalse(any(f["ruleId"] == "docker.curl-pipe-shell" for f in findings))


class FindingIdTests(unittest.TestCase):
    def test_deterministic_for_identical_input(self) -> None:
        a = scanner._finding_id("docker.root-user", "Dockerfile", 1, 1, "DS-0002")
        b = scanner._finding_id("docker.root-user", "Dockerfile", 1, 1, "DS-0002")
        self.assertEqual(a, b)

    def test_distinct_discriminators_get_distinct_ids(self) -> None:
        a = scanner._finding_id("docker.apt-upgrade", "Dockerfile", 3, 5, "3")
        b = scanner._finding_id("docker.apt-upgrade", "Dockerfile", 10, 12, "10")
        self.assertNotEqual(a, b)


class ConsistencyTests(unittest.TestCase):
    def test_every_trivy_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        for rule in scanner.TRIVY_RULES.values():
            for ref in rule.references:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{rule.rule_id} cites {ref}")

    def test_every_custom_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        from rules import CUSTOM_RULES

        for rule in CUSTOM_RULES:
            for ref in rule.references:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{rule.rule_id} cites {ref}")

    def test_every_rule_id_matches_naming_convention(self) -> None:
        import re

        from rules import CUSTOM_RULES

        pattern = re.compile(r"^docker\.[a-z0-9-]+$")
        all_rule_ids = [r.rule_id for r in scanner.TRIVY_RULES.values()] + [r.rule_id for r in CUSTOM_RULES]
        for rule_id in all_rule_ids:
            self.assertTrue(pattern.match(rule_id), rule_id)

    def test_no_duplicate_rule_ids(self) -> None:
        from rules import CUSTOM_RULES

        all_rule_ids = [r.rule_id for r in scanner.TRIVY_RULES.values()] + [r.rule_id for r in CUSTOM_RULES]
        self.assertEqual(len(all_rule_ids), len(set(all_rule_ids)))


@unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text(VULNERABLE_DOCKERFILE, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([tmp])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(len(parsed), 6)

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = scanner.main(["/tmp/definitely-does-not-exist-009-dockerfile"])
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
