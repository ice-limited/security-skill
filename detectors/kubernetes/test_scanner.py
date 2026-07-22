"""Tests for the Kubernetes detector: real Trivy subprocess calls (not
mocked — see plans/009-docker-skill.md's kickoff note on why, reused
verbatim for this plan), result-to-finding mapping, schema conformance,
error handling, and native Helm-chart scanning via a real
`helm create`-generated chart (not hand-typed YAML — per มิ้นท์'s QA
requirement at the plan 010 kickoff).

Requires the real `trivy` CLI on PATH (and network access for its
first run, to fetch its checks bundle); the Helm-specific tests also
require the real `helm` CLI on PATH, but are independently skippable if
it's absent. Run with: python3 -m unittest test_scanner -v (from
inside detectors/kubernetes/).
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
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


def _helm_available() -> bool:
    return shutil.which("helm") is not None


ALL_NINE_RULE_IDS = {
    "kubernetes.host-network-access",
    "kubernetes.host-pid-access",
    "kubernetes.privileged-container",
    "kubernetes.hostpath-volume",
    "kubernetes.root-user",
    "kubernetes.unpinned-image-tag",
    "kubernetes.missing-cpu-limit",
    "kubernetes.missing-memory-limit",
    "kubernetes.writable-root-filesystem",
}

# Deliberately obvious/synthetic manifest, not real-world content —
# enough for every one of this plan's 8 curated Trivy checks to
# actually fire, not just "look" vulnerable. Verified for real against
# this exact manifest at implementation (see plans/010-kubernetes-skill.md).
VULNERABLE_DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: myregistry/myapp:latest
          securityContext:
            privileged: true
            runAsUser: 0
            readOnlyRootFilesystem: false
          volumeMounts:
            - name: hostvol
              mountPath: /host
      volumes:
        - name: hostvol
          hostPath:
            path: /
"""

CLEAN_DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: clean-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: clean-app
  template:
    metadata:
      labels:
        app: clean-app
    spec:
      containers:
        - name: app
          image: myregistry/myapp:1.4.2
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "250m"
              memory: "128Mi"
"""

# Deliberately a *different* single finding from VULNERABLE_DEPLOYMENT
# (only the unpinned image tag, none of the others) so a multi-directory
# scan test can positively confirm both directories were actually
# scanned — mirrors the exact test-quality lesson 009 learned during
# mutation testing (a clean second directory wouldn't distinguish
# "scanned but clean" from "never scanned at all").
DIFFERENTLY_VULNERABLE_DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: differently-vulnerable-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: differently-vulnerable-app
  template:
    metadata:
      labels:
        app: differently-vulnerable-app
    spec:
      containers:
        - name: app
          image: myregistry/myapp:latest
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
"""

# No securityContext block at all — arguably the *more* common
# real-world shape than VULNERABLE_DEPLOYMENT's explicit
# `runAsUser: 0`/`readOnlyRootFilesystem: false` (most manifests simply
# omit securityContext rather than setting it insecurely). Verified for
# real during the "test plan 010" round that Trivy's root-user/
# writable-root-filesystem checks fire against the *implicit* default
# too, not just an explicit insecure value — this locks that in.
NO_SECURITY_CONTEXT_POD = """apiVersion: v1
kind: Pod
metadata:
  name: bare-pod
spec:
  containers:
    - name: app
      image: myregistry/myapp:2.3.1
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
"""

# Two containers in one pod, both vulnerable in the *same* way (both
# root) — verifies finding_id() doesn't collide across containers.
# Found worth checking during the "test plan 010" round because
# finding_id()'s discriminator is just the Trivy check ID, not a
# container name/index — it only stays collision-free because Trivy
# itself reports a distinct CauseMetadata line range per container, a
# fact this test locks in rather than assumes.
TWO_ROOT_CONTAINERS_POD = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: both-root
spec:
  replicas: 1
  selector:
    matchLabels:
      app: both-root
  template:
    metadata:
      labels:
        app: both-root
    spec:
      containers:
        - name: first
          image: myregistry/first:2.0.0
          securityContext:
            runAsUser: 0
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
        - name: second
          image: myregistry/second:3.0.0
          securityContext:
            runAsUser: 0
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
"""

# Not a Kubernetes manifest at all (no apiVersion/kind) — e.g. a bare
# Helm values.yaml sitting outside a chart, or an unrelated config
# file that happens to live alongside real manifests in the same
# directory.
NOT_A_KUBERNETES_MANIFEST = """image:
  repository: myapp
  tag: latest
replicaCount: 3
"""

# A CronJob's pod template is nested much deeper
# (spec.jobTemplate.spec.template.spec) than a Deployment's — verifies
# this plan's checks aren't accidentally Deployment-specific.
VULNERABLE_CRONJOB = """apiVersion: batch/v1
kind: CronJob
metadata:
  name: cron
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          hostPID: true
          containers:
            - name: app
              image: myregistry/myapp:latest
"""

# Verified for real during the "test plan 010" round: Trivy's `config`
# scan does NOT recognize the `kind: List` bundling pattern (a single
# document with an `items:` array of resources, distinct from
# `---`-separated multi-document YAML, which *is* recognized — see
# test_multidoc_yaml_is_recognized_and_gives_correct_line_numbers
# below) — it reports zero config files detected and produces no
# Results at all for the file, even though the embedded Pod is clearly
# vulnerable (hostNetwork: true). This is a genuine Trivy limitation,
# not a bug in this module — documented here so a future maintainer
# knows it's a known, verified gap, not an accidental regression. If a
# future Trivy version starts recognizing `kind: List`, this test will
# start failing, which is the signal to revisit this limitation.
KIND_LIST_BUNDLE = """apiVersion: v1
kind: List
items:
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: from-list
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: from-list
      template:
        metadata:
          labels:
            app: from-list
        spec:
          hostNetwork: true
          containers:
            - name: app
              image: myregistry/myapp:latest
"""


class PerRuleDetectionTests(unittest.TestCase):
    def _write(self, tmp: str, content: str, name: str = "deployment.yaml") -> Path:
        path = Path(tmp) / name
        path.write_text(content, encoding="utf-8")
        return path

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_finds_all_nine_curated_rules_in_one_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, VULNERABLE_DEPLOYMENT)
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(rule_ids, ALL_NINE_RULE_IDS, rule_ids)
        for f in findings:
            self.assertEqual(f["subSkill"], "kubernetes")
            self.assertEqual(f["artifactType"], "kubernetes-yaml")

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_clean_manifest_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, CLEAN_DEPLOYMENT)
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [])

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_scanning_two_separate_directories_aggregates_findings_from_both(self) -> None:
        # Regression test: trivy config rejects more than one target
        # per invocation ("multiple targets cannot be specified") —
        # scan_paths() must invoke it once per path and aggregate.
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            self._write(tmp_a, VULNERABLE_DEPLOYMENT)
            self._write(tmp_b, DIFFERENTLY_VULNERABLE_DEPLOYMENT)
            findings = scanner.scan_paths([tmp_a, tmp_b])
        rule_ids_a = {f["ruleId"] for f in findings if tmp_a in f["location"]["file"]}
        rule_ids_b = {f["ruleId"] for f in findings if tmp_b in f["location"]["file"]}
        self.assertEqual(rule_ids_b, {"kubernetes.unpinned-image-tag"}, rule_ids_b)
        self.assertTrue(rule_ids_a.issuperset({"kubernetes.host-network-access", "kubernetes.privileged-container"}))

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_container_with_no_security_context_at_all_still_flags_root_and_writable_fs(self) -> None:
        # The more realistic real-world shape: most manifests omit
        # securityContext entirely rather than setting it insecurely.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, NO_SECURITY_CONTEXT_POD)
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertIn("kubernetes.root-user", rule_ids)
        self.assertIn("kubernetes.writable-root-filesystem", rule_ids)

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_two_containers_vulnerable_the_same_way_get_distinct_finding_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, TWO_ROOT_CONTAINERS_POD)
            findings = scanner.scan_paths([tmp])
        root_findings = [f for f in findings if f["ruleId"] == "kubernetes.root-user"]
        self.assertEqual(len(root_findings), 2, root_findings)
        self.assertNotEqual(root_findings[0]["findingId"], root_findings[1]["findingId"])
        self.assertNotEqual(root_findings[0]["location"], root_findings[1]["location"])

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_non_kubernetes_yaml_produces_no_findings_and_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, NOT_A_KUBERNETES_MANIFEST, name="values.yaml")
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [])

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_multidoc_yaml_is_recognized_and_gives_correct_line_numbers(self) -> None:
        # `---`-separated multi-document YAML (a Service + a Deployment
        # in one file) — distinct from the `kind: List` bundling
        # pattern below, which Trivy does *not* recognize.
        content = (
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: app-svc\nspec:\n"
            "  selector:\n    app: app\n  ports:\n    - port: 80\n---\n" + VULNERABLE_DEPLOYMENT
        )
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, content)
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(rule_ids, ALL_NINE_RULE_IDS, rule_ids)

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_cronjob_nested_pod_template_is_scanned_correctly(self) -> None:
        # A CronJob's pod template lives much deeper
        # (spec.jobTemplate.spec.template.spec) than a Deployment's —
        # verifies this plan's checks aren't accidentally
        # Deployment-specific.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, VULNERABLE_CRONJOB)
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertIn("kubernetes.host-pid-access", rule_ids)
        self.assertIn("kubernetes.unpinned-image-tag", rule_ids)

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_kind_list_bundling_is_not_recognized_a_known_trivy_gap(self) -> None:
        # Documents a real, verified Trivy limitation (not a bug in
        # this module): `kind: List` bundles are silently not
        # recognized as containing Kubernetes resources at all, so a
        # vulnerable Pod defined this way produces zero findings —
        # indistinguishable from "scanned and clean." See the
        # KIND_LIST_BUNDLE docstring above and
        # detectors/kubernetes/README.md's "Known limitations" section.
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, KIND_LIST_BUNDLE)
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [], findings)


@unittest.skipUnless(_trivy_available() and _helm_available(), "requires the real trivy and helm CLIs on PATH")
class HelmChartTests(unittest.TestCase):
    """Uses the real `helm create` CLI to generate a genuine chart
    skeleton, not hand-typed chart YAML — per มิ้นท์'s QA requirement at
    the plan 010 kickoff (mirrors 008's "real, tool-generated fixtures"
    discipline). Verifies Trivy really renders and scans Helm charts
    natively: no `helm template` shell-out or `helm` CLI dependency at
    scan time, only at fixture-generation time in this test."""

    def _generate_vulnerable_chart(self, tmp: str) -> Path:
        subprocess.run(["helm", "create", "demo-chart"], cwd=tmp, check=True, capture_output=True, text=True)
        chart_dir = Path(tmp) / "demo-chart"
        values_path = chart_dir / "values.yaml"
        values = values_path.read_text(encoding="utf-8")
        values = values.replace('tag: ""', 'tag: "latest"')
        values = values.replace(
            "securityContext: {}",
            "securityContext:\n  runAsUser: 0\n  privileged: true\n  readOnlyRootFilesystem: false",
            1,
        )
        values_path.write_text(values, encoding="utf-8")
        return chart_dir

    def test_helm_chart_is_natively_rendered_and_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chart_dir = self._generate_vulnerable_chart(tmp)
            findings = scanner.scan_paths([str(chart_dir)])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertTrue(
            rule_ids.issuperset({"kubernetes.privileged-container", "kubernetes.root-user", "kubernetes.unpinned-image-tag"}),
            rule_ids,
        )
        for f in findings:
            self.assertEqual(f["artifactType"], "helm")
            self.assertTrue(f["location"]["file"].endswith("templates/deployment.yaml"), f["location"]["file"])


@unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
class SchemaConformanceTests(unittest.TestCase):
    def test_real_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deployment.yaml"
            path.write_text(VULNERABLE_DEPLOYMENT, encoding="utf-8")
            findings = scanner.scan_paths([str(tmp)])
        self.assertEqual(len(findings), 9)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


@unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
class ErrorHandlingTests(unittest.TestCase):
    def test_bad_path_raises_scanner_error(self) -> None:
        with self.assertRaises(ScannerError):
            scanner.scan_paths(["/tmp/definitely-does-not-exist-010-k8s-manifest"])

    def test_missing_trivy_binary_raises_actionable_error(self) -> None:
        with mock.patch("scanner._tw.shutil.which", return_value=None):
            with self.assertRaises(ScannerError) as ctx:
                scanner.run_trivy("irrelevant")
        self.assertIn("brew install trivy", str(ctx.exception))

    def test_returncode_nonzero_raises_even_with_valid_json_stdout(self) -> None:
        fake_proc = mock.Mock(returncode=1, stdout='{"Results": []}', stderr="mocked failure")
        with mock.patch("scanner._tw.subprocess.run", return_value=fake_proc):
            with self.assertRaises(ScannerError):
                scanner.run_trivy("irrelevant")


class MappingTests(unittest.TestCase):
    """Pure-function unit tests — no trivy subprocess needed, fast and
    deterministic."""

    def test_trivy_severity_mapping(self) -> None:
        for raw, expected in [("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")]:
            misconfig = {"ID": "KSV-0017", "Severity": raw, "CauseMetadata": {"StartLine": 1, "EndLine": 1}}
            finding = scanner.map_trivy_misconfig(misconfig, "deployment.yaml", "kubernetes-yaml", "0.72.0")
            self.assertEqual(finding["severity"], expected)

    def test_unknown_trivy_check_id_returns_none(self) -> None:
        # Trivy reports ~23 Kubernetes checks total; this plan
        # deliberately curates to 8 — anything not in the curated
        # catalog is silently skipped, not an error.
        misconfig = {"ID": "KSV-0001", "Severity": "MEDIUM", "CauseMetadata": {}}
        self.assertIsNone(scanner.map_trivy_misconfig(misconfig, "deployment.yaml", "kubernetes-yaml", "0.72.0"))

    def test_resolve_target_path_for_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolved = scanner._resolve_target_path(tmp, "deployment.yaml")
        self.assertEqual(str(resolved), str(Path(tmp) / "deployment.yaml"))

    def test_resolve_target_path_for_single_file_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "deployment.yaml"
            file_path.write_text(CLEAN_DEPLOYMENT, encoding="utf-8")
            resolved = scanner._resolve_target_path(str(file_path), "deployment.yaml")
        self.assertEqual(str(resolved), str(file_path))

    def test_artifact_type_maps_kubernetes_trivy_type_to_kubernetes_yaml(self) -> None:
        self.assertEqual(scanner._ARTIFACT_TYPE_BY_TRIVY_TYPE["kubernetes"], "kubernetes-yaml")

    def test_artifact_type_maps_helm_trivy_type_to_helm(self) -> None:
        self.assertEqual(scanner._ARTIFACT_TYPE_BY_TRIVY_TYPE["helm"], "helm")


class ConsistencyTests(unittest.TestCase):
    def test_every_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        for rule in scanner.TRIVY_RULES.values():
            for ref in rule.references:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{rule.rule_id} cites {ref}")

    def test_every_rule_id_matches_naming_convention(self) -> None:
        import re

        pattern = re.compile(r"^kubernetes\.[a-z0-9-]+$")
        for rule in scanner.TRIVY_RULES.values():
            self.assertTrue(pattern.match(rule.rule_id), rule.rule_id)

    def test_no_duplicate_rule_ids(self) -> None:
        all_rule_ids = [r.rule_id for r in scanner.TRIVY_RULES.values()]
        self.assertEqual(len(all_rule_ids), len(set(all_rule_ids)))

    def test_covers_exactly_the_nine_curated_check_ids(self) -> None:
        # 8 CONTEXT.md §7 checklist items, one of which (resource
        # limits) splits into 2 rule_ids (CPU/memory each reported as
        # an independent Trivy check) — 9 curated Trivy check IDs total.
        self.assertEqual(set(scanner.TRIVY_RULES.keys()), {
            "KSV-0009", "KSV-0010", "KSV-0017", "KSV-0023",
            "KSV-0012", "KSV-0013", "KSV-0011", "KSV-0018", "KSV-0014",
        })


@unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deployment.yaml"
            path.write_text(VULNERABLE_DEPLOYMENT, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([tmp])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(len(parsed), 9)

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = scanner.main(["/tmp/definitely-does-not-exist-010-k8s-manifest"])
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
