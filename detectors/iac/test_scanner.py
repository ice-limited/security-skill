"""Tests for the IaC detector: real Checkov subprocess calls (not
mocked — see plans/011-iac-skill.md's kickoff note on why), result-to-
finding mapping, the framework-specific check-ID nuance, schema
conformance, and error handling.

Requires the real `checkov` CLI on PATH (`pip install checkov`, see
requirements.txt). Run with: python3 -m unittest test_scanner -v (from
inside detectors/iac/).
"""

from __future__ import annotations

import io
import json
import os
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


def _checkov_available() -> bool:
    return shutil.which("checkov") is not None


# Deliberately obvious/synthetic fixtures, not real-world content —
# enough for Checkov to actually fire, not just "look" vulnerable.
# Verified for real against these exact fixtures at implementation
# (see plans/011-iac-skill.md).
AWS_VULNERABLE_TF = """resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
}

resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

resource "aws_iam_policy" "wide" {
  name = "wide-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_security_group" "open" {
  name = "open-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

AWS_CLEAN_TF = """resource "aws_s3_bucket" "clean" {
  bucket = "my-clean-bucket"
}

resource "aws_s3_bucket_public_access_block" "clean" {
  bucket                  = aws_s3_bucket.clean.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_policy" "narrow" {
  name = "narrow-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = [aws_s3_bucket.clean.arn]
    }]
  })
}

resource "aws_security_group" "restricted" {
  name = "restricted-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"""

AZURE_VULNERABLE_TF = """resource "azurerm_storage_account" "sa" {
  name                             = "mystorageacct"
  account_tier                     = "Standard"
  account_replication_type         = "LRS"
  allow_nested_items_to_be_public  = true
}

resource "azurerm_network_security_rule" "open" {
  name                         = "open-rule"
  priority                     = 100
  direction                    = "Inbound"
  access                       = "Allow"
  protocol                     = "Tcp"
  source_port_range            = "*"
  destination_port_range       = "22"
  source_address_prefix        = "*"
  destination_address_prefix   = "*"
  resource_group_name          = "rg"
  network_security_group_name  = "nsg"
}

resource "azurerm_role_definition" "wide" {
  name  = "wide-role"
  scope = "/"
  permissions {
    actions = ["*"]
  }
  assignable_scopes = ["/"]
}
"""

GCP_VULNERABLE_TF = """resource "google_storage_bucket" "b" {
  name     = "my-gcp-bucket"
  location = "US"
}

resource "google_storage_bucket_iam_binding" "public" {
  bucket  = google_storage_bucket.b.name
  role    = "roles/storage.admin"
  members = ["allUsers"]
}

resource "google_compute_firewall" "open" {
  name    = "open-fw"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_project_iam_binding" "wide" {
  project = "my-project"
  role    = "roles/owner"
  members = ["allUsers"]
}
"""

# Same logical IAM-privilege-escalation + public-S3 concern as
# AWS_VULNERABLE_TF, expressed as CloudFormation — Checkov reports this
# via *different* check IDs than the Terraform equivalent
# (CKV_AWS_110 vs CKV_AWS_286 for privilege escalation), verified for
# real at implementation. See test_cloudformation_uses_different_
# check_id_for_same_rule below.
AWS_VULNERABLE_CFN = """AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: wide-policy
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
      Roles:
        - my-role
  MySG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: open sg
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""

ANSIBLE_VULNERABLE_PLAYBOOK = """- hosts: all
  tasks:
    - name: download without cert validation
      get_url:
        url: https://example.com/file.sh
        dest: /tmp/file.sh
        validate_certs: false
    - name: apt without gpg check
      apt:
        name: somepkg
        allow_unauthenticated: true
"""

ANSIBLE_CLEAN_PLAYBOOK = """- hosts: all
  tasks:
    - name: download with cert validation
      get_url:
        url: https://example.com/file.sh
        dest: /tmp/file.sh
    - name: apt with signature check
      apt:
        name: somepkg
"""

# Deliberately a *different* single finding from AWS_VULNERABLE_TF
# (only the open-SSH-ingress rule, none of the IAM/S3 ones) so a
# multi-path scan test can positively confirm both paths were actually
# scanned — mirrors 009's own "two distinctly vulnerable fixtures"
# lesson from mutation testing.
AWS_DIFFERENTLY_VULNERABLE_TF = """resource "aws_security_group" "open2" {
  name = "open-sg-2"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


class PerCloudDetectionTests(unittest.TestCase):
    def _write(self, tmp: str, content: str, name: str) -> Path:
        path = Path(tmp) / name
        path.write_text(content, encoding="utf-8")
        return path

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_aws_vulnerable_fixture_fires_all_seven_curated_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, AWS_VULNERABLE_TF, "main.tf")
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(
            rule_ids,
            {
                "iac.aws-iam-wildcard-actions",
                "iac.aws-iam-full-admin-privileges",
                "iac.aws-iam-wildcard-resource",
                "iac.aws-iam-privilege-escalation",
                "iac.aws-s3-public-read-acl",
                "iac.aws-s3-missing-public-access-block",
                "iac.aws-open-ssh-ingress",
            },
            rule_ids,
        )
        for f in findings:
            self.assertEqual(f["subSkill"], "iac")
            self.assertEqual(f["artifactType"], "terraform")

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_aws_clean_fixture_produces_no_curated_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, AWS_CLEAN_TF, "main.tf")
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [])

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_azure_vulnerable_fixture_fires_all_four_curated_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, AZURE_VULNERABLE_TF, "main.tf")
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(
            rule_ids,
            {
                "iac.azure-custom-owner-role",
                "iac.azure-storage-public-access",
                "iac.azure-storage-blob-public-access",
                "iac.azure-open-ssh-nsg",
            },
            rule_ids,
        )

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_gcp_vulnerable_fixture_fires_all_five_curated_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, GCP_VULNERABLE_TF, "main.tf")
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(
            rule_ids,
            {
                "iac.gcp-project-basic-role",
                "iac.gcp-project-iam-service-account-impersonation",
                "iac.gcp-storage-public-access",
                "iac.gcp-storage-missing-public-access-prevention",
                "iac.gcp-open-ssh-firewall",
            },
            rule_ids,
        )

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_ansible_vulnerable_playbook_fires_curated_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, ANSIBLE_VULNERABLE_PLAYBOOK, "playbook.yml")
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(
            rule_ids,
            {"iac.ansible-get-url-cert-validation-disabled", "iac.ansible-apt-unauthenticated-packages"},
            rule_ids,
        )
        for f in findings:
            self.assertEqual(f["artifactType"], "ansible")

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_ansible_clean_playbook_produces_no_curated_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, ANSIBLE_CLEAN_PLAYBOOK, "playbook.yml")
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [])

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_cloudformation_uses_different_check_id_for_same_rule(self) -> None:
        # The real, verified framework-specific-check-ID nuance: IAM
        # privilege escalation is CKV_AWS_286 in Terraform but
        # CKV_AWS_110 in CloudFormation — both must map to the *same*
        # rule_id via rules.py's check_ids dict.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, AWS_VULNERABLE_CFN, "template.yaml")
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertIn("iac.aws-iam-privilege-escalation", rule_ids)
        self.assertIn("iac.aws-iam-wildcard-actions", rule_ids)
        for f in findings:
            self.assertEqual(f["artifactType"], "cloudformation")

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_cloudformation_file_path_is_resolved_to_absolute(self) -> None:
        # Real, verified Checkov quirk: file_abs_path is left relative
        # (not actually absolute) specifically for CloudFormation,
        # unlike Terraform/Ansible where it's genuinely absolute.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, AWS_VULNERABLE_CFN, "template.yaml")
            findings = scanner.scan_paths([tmp])
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(Path(f["location"]["file"]).is_absolute(), f["location"]["file"])

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_cloudformation_stays_absolute_even_when_caller_passes_a_relative_path(self) -> None:
        # Isolates the exact bug scenario: tempfile.TemporaryDirectory()
        # always yields an already-absolute path, so a naive fixture
        # calling scan_paths([tmp]) never actually exercises the case
        # that broke — a *caller* passing a relative path string (the
        # normal case for e.g. a CLI invocation from within a repo
        # checkout). Changes CWD into the fixture dir and passes a bare
        # relative filename to reproduce that real scenario.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, AWS_VULNERABLE_CFN, "template.yaml")
            old_cwd = Path.cwd()
            os.chdir(tmp)
            try:
                findings = scanner.scan_paths(["template.yaml"])
            finally:
                os.chdir(old_cwd)
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(Path(f["location"]["file"]).is_absolute(), f["location"]["file"])

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_scanning_two_separate_directories_aggregates_findings_from_both(self) -> None:
        # Regression test: checkov garbles its own JSON output when
        # given more than one -d/-f value in a single invocation (see
        # run_checkov()'s docstring) — scan_paths() must invoke it once
        # per path and aggregate. Uses two *distinctly* vulnerable
        # fixtures so the assertion can't be satisfied by silently
        # skipping one directory (mirrors 009's own mutation-tested
        # lesson).
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            self._write(tmp_a, AWS_VULNERABLE_TF, "main.tf")
            self._write(tmp_b, AWS_DIFFERENTLY_VULNERABLE_TF, "main.tf")
            findings = scanner.scan_paths([tmp_a, tmp_b])
        rule_ids_a = {f["ruleId"] for f in findings if tmp_a in f["location"]["file"]}
        rule_ids_b = {f["ruleId"] for f in findings if tmp_b in f["location"]["file"]}
        self.assertIn("iac.aws-iam-wildcard-actions", rule_ids_a)
        self.assertEqual(rule_ids_b, {"iac.aws-open-ssh-ingress"}, rule_ids_b)

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_mixed_directory_with_all_three_frameworks_is_scanned_correctly(self) -> None:
        # Real, verified Checkov quirk: -o json's top-level shape is
        # polymorphic — a bare summary dict (nothing matched), a single
        # dict (exactly one framework matched), or a list of dicts
        # (more than one framework matched within the same path). A
        # directory with Terraform + CloudFormation + Ansible content
        # together exercises the "list of dicts" shape specifically.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, AWS_VULNERABLE_TF, "main.tf")
            self._write(tmp, AWS_VULNERABLE_CFN, "template.yaml")
            self._write(tmp, ANSIBLE_VULNERABLE_PLAYBOOK, "playbook.yml")
            findings = scanner.scan_paths([tmp])
        artifact_types = {f["artifactType"] for f in findings}
        self.assertEqual(artifact_types, {"terraform", "cloudformation", "ansible"}, artifact_types)

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_empty_existing_directory_produces_no_findings_and_does_not_crash(self) -> None:
        # Real, verified Checkov quirk: an empty existing directory and
        # a *nonexistent* directory report the identical zero-count
        # JSON shape and exit 0 — this test locks in the "legitimately
        # empty" side; test_bad_path_raises_scanner_error below locks
        # in that a nonexistent path is still caught (via our own
        # Path.exists() check, not checkov's own signaling).
        with tempfile.TemporaryDirectory() as tmp:
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [])

    @unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
    def test_malformed_file_does_not_crash_and_valid_sibling_still_scans(self) -> None:
        # Real, verified behavior found during the "test plan 011"
        # round: a directory containing one syntactically-broken .tf
        # file alongside a valid one does *not* fail the whole scan —
        # checkov silently records a parsing_errors count for the
        # broken file (not surfaced as a finding.schema.json finding;
        # no schema slot exists for "this file failed to parse") while
        # still scanning and reporting on the valid sibling file
        # normally. Locking this in as documented behavior, not
        # "fixing" it — matches 010's own "kind: List" precedent of
        # documenting a real tool-behavior boundary via a test rather
        # than building extra logic to paper over it.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "resource \"aws_s3_bucket\" \"x\" {\n  not valid hcl {{{\n", "broken.tf")
            self._write(tmp, AWS_DIFFERENTLY_VULNERABLE_TF, "good.tf")
            findings = scanner.scan_paths([tmp])
        self.assertEqual({f["ruleId"] for f in findings}, {"iac.aws-open-ssh-ingress"})
        self.assertTrue(all("good.tf" in f["location"]["file"] for f in findings))


@unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
class SchemaConformanceTests(unittest.TestCase):
    def test_real_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "main.tf"
            path.write_text(AWS_VULNERABLE_TF, encoding="utf-8")
            findings = scanner.scan_paths([str(tmp)])
        self.assertEqual(len(findings), 7)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


@unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
class ErrorHandlingTests(unittest.TestCase):
    def test_bad_path_raises_scanner_error(self) -> None:
        with self.assertRaises(ScannerError):
            scanner.scan_paths(["/tmp/definitely-does-not-exist-011-iac"])

    def test_missing_checkov_binary_raises_actionable_error(self) -> None:
        with mock.patch("scanner.shutil.which", return_value=None):
            with self.assertRaises(ScannerError) as ctx:
                scanner.run_checkov("irrelevant")
        self.assertIn("pip install checkov", str(ctx.exception))

    def test_returncode_two_raises(self) -> None:
        # Isolates the return-code check itself (mirrors the same
        # test-quality lesson from 008/009: a bad path also produces
        # different output, which would independently fail parsing and
        # mask whether the return-code check does anything).
        fake_proc = mock.Mock(returncode=2, stdout="", stderr="mocked CLI error")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("scanner.subprocess.run", return_value=fake_proc):
                with self.assertRaises(ScannerError):
                    scanner.run_checkov(tmp)

    def test_returncode_zero_and_one_are_both_accepted(self) -> None:
        # Checkov's own convention: 1 means "ran cleanly AND has
        # findings," not a failure.
        for code in (0, 1):
            fake_proc = mock.Mock(returncode=code, stdout='{"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0, "checkov_version": "3.3.8"}', stderr="")
            with tempfile.TemporaryDirectory() as tmp:
                with mock.patch("scanner.subprocess.run", return_value=fake_proc):
                    self.assertEqual(scanner.run_checkov(tmp), [])


class MappingTests(unittest.TestCase):
    """Pure-function unit tests — no checkov subprocess needed, fast
    and deterministic."""

    def _check(self, check_id: str, start=10, end=20) -> dict:
        return {"check_id": check_id, "file_abs_path": "/some/file.tf", "file_line_range": [start, end]}

    def test_unknown_check_id_returns_none(self) -> None:
        self.assertIsNone(scanner.map_checkov_check(self._check("CKV_AWS_9999"), "terraform", "3.3.8"))

    def test_known_check_id_wrong_framework_returns_none(self) -> None:
        # CKV_AWS_88 is curated only for "ansible" (an ansible-module
        # check) — must not accidentally match if seen under "terraform".
        self.assertIsNone(scanner.map_checkov_check(self._check("CKV_AWS_88"), "terraform", "3.3.8"))

    def test_known_check_id_correct_framework_maps(self) -> None:
        finding = scanner.map_checkov_check(self._check("CKV_AWS_63"), "terraform", "3.3.8")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["ruleId"], "iac.aws-iam-wildcard-actions")
        self.assertEqual(finding["severity"], "High")

    def test_missing_file_line_range_defaults_to_line_1(self) -> None:
        check = {"check_id": "CKV_AWS_63", "file_abs_path": "/some/file.tf"}
        finding = scanner.map_checkov_check(check, "terraform", "3.3.8")
        self.assertEqual(finding["location"], {"file": "/some/file.tf", "startLine": 1, "endLine": 1})

    def test_resolve_file_path_makes_relative_path_absolute(self) -> None:
        # Direct unit test of the CloudFormation file_abs_path bug fix.
        check = {"file_abs_path": "template.yaml"}
        resolved = scanner._resolve_file_path(check)
        self.assertTrue(Path(resolved).is_absolute(), resolved)
        self.assertTrue(resolved.endswith("template.yaml"))

    def test_resolve_file_path_leaves_already_absolute_path_correct(self) -> None:
        # Compares via resolve() on both sides, not raw string
        # equality — on macOS, /tmp is itself a symlink to /private/tmp,
        # so Path.resolve() legitimately changes the string
        # representation (correct, documented behavior) without
        # changing which file it refers to.
        with tempfile.TemporaryDirectory() as tmp:
            real_file = Path(tmp) / "main.tf"
            real_file.write_text("", encoding="utf-8")
            check = {"file_abs_path": str(real_file)}
            resolved = scanner._resolve_file_path(check)
        self.assertEqual(Path(resolved), real_file.resolve())


class RunCheckovOutputNormalizationTests(unittest.TestCase):
    """Direct tests of run_checkov()'s three-shape JSON normalization
    — mocked subprocess output, since triggering all three shapes for
    real requires very specific fixture combinations already covered
    end-to-end in PerCloudDetectionTests above. These isolate the
    normalization logic itself."""

    def _run_with_stdout(self, stdout: str):
        fake_proc = mock.Mock(returncode=0, stdout=stdout, stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("scanner.subprocess.run", return_value=fake_proc):
                return scanner.run_checkov(tmp)

    def test_bare_summary_dict_with_no_check_type_normalizes_to_empty_list(self) -> None:
        result = self._run_with_stdout('{"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0, "checkov_version": "3.3.8"}')
        self.assertEqual(result, [])

    def test_single_dict_with_check_type_normalizes_to_one_element_list(self) -> None:
        result = self._run_with_stdout('{"check_type": "terraform", "results": {"failed_checks": []}, "summary": {}}')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["check_type"], "terraform")

    def test_list_of_dicts_passes_through_unchanged(self) -> None:
        result = self._run_with_stdout(
            '[{"check_type": "terraform", "results": {"failed_checks": []}, "summary": {}},'
            ' {"check_type": "ansible", "results": {"failed_checks": []}, "summary": {}}]'
        )
        self.assertEqual(len(result), 2)
        self.assertEqual({r["check_type"] for r in result}, {"terraform", "ansible"})


class ConsistencyTests(unittest.TestCase):
    def test_every_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        for rule in scanner.CHECKOV_RULES:
            for ref in rule.references:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{rule.rule_id} cites {ref}")

    def test_every_rule_id_matches_naming_convention(self) -> None:
        import re

        pattern = re.compile(r"^iac\.[a-z0-9-]+$")
        for rule in scanner.CHECKOV_RULES:
            self.assertTrue(pattern.match(rule.rule_id), rule.rule_id)

    def test_no_duplicate_rule_ids(self) -> None:
        all_rule_ids = [r.rule_id for r in scanner.CHECKOV_RULES]
        self.assertEqual(len(all_rule_ids), len(set(all_rule_ids)))

    def test_no_duplicate_check_id_per_framework(self) -> None:
        # Two curated rules must never claim the same (framework,
        # check_id) pair — the reverse index would silently let the
        # later one win, masking the earlier rule entirely.
        seen: dict[tuple[str, str], str] = {}
        for rule in scanner.CHECKOV_RULES:
            for framework, check_id in rule.check_ids.items():
                key = (framework, check_id)
                self.assertNotIn(key, seen, f"{key} claimed by both {seen.get(key)} and {rule.rule_id}")
                seen[key] = rule.rule_id

    def test_every_rule_severity_is_a_valid_schema_enum_value(self) -> None:
        # SchemaConformanceTests only exercises the AWS fixture's 7
        # rules end-to-end — a typo'd severity on any of the other 16
        # (Azure/GCP/Ansible) rules would never surface without this
        # cheap, subprocess-free check across all 23.
        valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
        for rule in scanner.CHECKOV_RULES:
            self.assertIn(rule.severity, valid_severities, rule.rule_id)

    def test_every_rule_has_at_least_one_check_id(self) -> None:
        for rule in scanner.CHECKOV_RULES:
            self.assertTrue(rule.check_ids, rule.rule_id)

    def test_every_check_id_framework_is_in_scope(self) -> None:
        for rule in scanner.CHECKOV_RULES:
            for framework in rule.check_ids:
                self.assertIn(framework, scanner.FRAMEWORKS, f"{rule.rule_id} claims unknown framework {framework}")


@unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "main.tf"
            path.write_text(AWS_VULNERABLE_TF, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([tmp])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(len(parsed), 7)

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = scanner.main(["/tmp/definitely-does-not-exist-011-iac"])
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
