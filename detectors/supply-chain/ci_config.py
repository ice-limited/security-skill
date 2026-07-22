"""Deterministic GitHub Actions workflow parsing for this plan's
config-presence checks: does a job that builds a container image also
sign it (Cosign) and generate an SBOM for it, and does the workflow
generate SLSA provenance anywhere?

**Design correction from the plan 014 kickoff**: the kickoff's design
assumed Checkov's own `CKV_GHA_5`/`CKV_GHA_6` (CosignArtifacts/
CosignSBOM checks) could be reused directly. Verified at implementation
that both are **non-functional in real usage** — a real bug, not a
narrow gap: their `scan_conf()` loop iterates the parsed `jobs:` dict
and unconditionally `return CheckResult.PASSED` the moment it
encounters Checkov's own `__startline__`/`__endline__` metadata keys
(which the parser injects into every mapping), discarding whatever
"a build step exists with no signing/SBOM step after it" state the
loop had already accumulated. Confirmed via three real, distinct
fixtures — a single-job unsigned build, a signed one, and a two-job
all-unsigned case — that these checks **never return FAILED**,
regardless of input. This module replaces them with hand-written
checks, mirroring 009's own precedent of writing custom rules when no
existing tool covers a needed gap. See plans/014-supply-chain-skill.md
and meetings/2026-07-22-2350-plan-014-kickoff.md in the
security-skill-workspace repo.

Uses `ruamel.yaml`'s round-trip loader for real line numbers, the same
technique 012 (API Skill) already established for OpenAPI spec parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML

# Same literal build-command/action patterns Checkov's own (buggy)
# CosignArtifacts/CosignSBOM checks use — verified these are the real
# patterns via reading checkov/github_actions/common/{build_actions,
# artifact_build}.py directly, reused here as plain constants (not an
# import from checkov, since this module owns its own detection logic
# now, not checkov's).
_BUILD_ACTIONS = ("docker/build-push-action", "docker/bake-action")
_BUILD_COMMANDS = ("docker build", "docker buildx build", "ko build", "buildah bud", "buildah build", "podman image build", "podman build", "nerdctl build")
_SIGN_MARKER = "cosign sign"
_SBOM_MARKERS = ("cosign attest", "anchore/sbom-action", "syft ", "cyclonedx")
_SLSA_PROVENANCE_MARKER = "slsa-framework/slsa-github-generator"

_yaml = YAML(typ="rt")


class WorkflowParseError(Exception):
    """Raised when the workflow file cannot be parsed at all — fail
    loud rather than silently reporting no findings, which would look
    identical to "parsed fine, nothing to flag"."""


@dataclass(frozen=True)
class JobBuildStatus:
    job_name: str
    line: int
    has_build_step: bool
    has_sign_step_after_build: bool
    has_sbom_step_after_build: bool


def load_workflow(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        doc = _yaml.load(text)
    except Exception as e:  # ruamel raises various yaml.YAMLError subclasses
        raise WorkflowParseError(f"{path}: not valid YAML: {e}") from e
    if not isinstance(doc, dict):
        raise WorkflowParseError(f"{path}: top-level document is not a mapping (got {type(doc).__name__})")
    return doc


def _step_is_build(step: dict) -> bool:
    uses = step.get("uses")
    if isinstance(uses, str) and any(action in uses for action in _BUILD_ACTIONS):
        return True
    run = step.get("run")
    if isinstance(run, str) and any(cmd in run for cmd in _BUILD_COMMANDS):
        return True
    return False


def _step_signs(step: dict) -> bool:
    run = step.get("run")
    return isinstance(run, str) and _SIGN_MARKER in run


def _step_generates_sbom(step: dict) -> bool:
    run = step.get("run")
    if isinstance(run, str) and any(marker in run for marker in _SBOM_MARKERS):
        return True
    uses = step.get("uses")
    return isinstance(uses, str) and "anchore/sbom-action" in uses


def analyze_jobs(workflow: dict) -> list[JobBuildStatus]:
    """Per job: does it build a container image, and — among steps
    *after* the first build step in that job — is there a signing step
    and/or an SBOM-generation step. A job with no build step at all is
    still returned (with `has_build_step=False`) so callers can filter,
    but is never itself a finding."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return []

    statuses = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            steps = []

        line = 1
        try:
            line = jobs.lc.data[job_name][0] + 1
        except (AttributeError, KeyError, TypeError):
            pass

        build_found = False
        signed = False
        sbom_generated = False
        for step in steps:
            if not isinstance(step, dict):
                continue
            if not build_found:
                if _step_is_build(step):
                    build_found = True
                continue
            if _step_signs(step):
                signed = True
            if _step_generates_sbom(step):
                sbom_generated = True

        statuses.append(
            JobBuildStatus(
                job_name=str(job_name),
                line=line,
                has_build_step=build_found,
                has_sign_step_after_build=signed,
                has_sbom_step_after_build=sbom_generated,
            )
        )

    return statuses


def has_slsa_provenance_generator(workflow: dict) -> bool:
    """Whether *any* job anywhere in the workflow references the
    official SLSA GitHub Actions provenance generator — checked
    workflow-wide, not per-job, since provenance generation is
    typically a separate downstream job depending on the build job's
    outputs, not the build job itself.

    Checks two distinct shapes, both real GitHub Actions syntax
    (verified with real fixtures at implementation — an earlier version
    of this function only checked the step-level shape and silently
    missed the job-level one, the far more common way this specific
    generator is actually invoked): a **job-level** reusable-workflow
    call (`jobs.<id>.uses: slsa-framework/...@ref`, no `steps:` for that
    job at all) and a **step-level** `uses:` inside a job's `steps:`
    list (less common for this particular generator, which is designed
    as a reusable *workflow*, but checked anyway for robustness)."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return False
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_uses = job.get("uses")
        if isinstance(job_uses, str) and _SLSA_PROVENANCE_MARKER in job_uses:
            return True
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str) and _SLSA_PROVENANCE_MARKER in uses:
                return True
    return False
