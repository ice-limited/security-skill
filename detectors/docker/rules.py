"""Docker/Dockerfile hardening rule catalog.

Three checks (`docker.unpinned-base-image`, `docker.root-user`,
`docker.missing-healthcheck`) are detected by Trivy's `config` scan
mode (github.com/aquasecurity/trivy, Apache-2.0) — Trivy gives true
line locations and its own severity, but its own check metadata has no
CWE mapping, so problem/impact/recommendation/references are
hand-authored here, the same shape as 006's own rule catalog (a small,
curated set of checks, not hundreds of tool-provided ones the way 007's
Semgrep pack or 008's osv-scanner findings are).

Three more checks (`docker.apt-upgrade`, `docker.curl-pipe-shell`,
`docker.add-instead-of-copy`) are custom, hand-written pattern rules —
verified at plan 009's kickoff that neither Trivy nor Hadolint has a
security-specific rule for these (Hadolint's related rules, DL3009 and
DL4006, are about apt-cache cleanup and shell `pipefail` — different
concerns).

See plans/009-docker-skill.md and
meetings/2026-07-22-1900-plan-009-kickoff.md in the
security-skill-workspace repo for design rationale.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TrivyRule:
    rule_id: str
    title: str
    problem: str
    impact: str
    recommendation: str
    references: list[dict]
    confidence: int


@dataclass(frozen=True)
class CustomRule:
    rule_id: str
    title: str
    pattern: re.Pattern
    problem: str
    impact: str
    recommendation: str
    references: list[dict]
    severity: str
    confidence: int
    # Whether backslash-continuation lines should be joined into one
    # logical line before matching — needed for RUN instructions that
    # wrap onto multiple physical lines (a very common real pattern,
    # verified against a real multi-line `curl | bash` fixture at
    # implementation).
    join_continuations: bool = False


# Trivy check IDs this plan maps to a curated finding — anything else
# Trivy reports (there are many more general-purpose checks in its
# `config` scan) is out of this plan's declared scope and not mapped.
TRIVY_RULES: dict[str, TrivyRule] = {
    "DS-0001": TrivyRule(
        rule_id="docker.unpinned-base-image",
        title="Base image uses an unpinned/mutable tag",
        problem="The base image in the FROM instruction uses 'latest' (or another mutable tag) instead of a pinned version.",
        impact=(
            "The image's actual content can change unpredictably between builds — a tag that was "
            "safe when first used may later resolve to a different, untested, or compromised image "
            "without any change to this Dockerfile."
        ),
        recommendation=(
            "Pin the base image to a specific, immutable version (ideally by digest, e.g. "
            "'ubuntu@sha256:...') rather than a mutable tag like 'latest'."
        ),
        references=[{"standard": "CWE", "id": "CWE-1357"}, {"standard": "OWASP-Top10", "id": "A03:2025"}],
        confidence=90,
    ),
    "DS-0002": TrivyRule(
        rule_id="docker.root-user",
        title="Container runs as the root user",
        problem="The last USER instruction (or the absence of one) leaves the container running as root.",
        impact=(
            "A process compromise inside the container has root privileges within it, making "
            "container-escape and host-impact scenarios more severe than they would be as an "
            "unprivileged user."
        ),
        recommendation=(
            "Add a non-root USER instruction (after creating the user/group if needed) before the "
            "container's entrypoint runs."
        ),
        references=[{"standard": "CWE", "id": "CWE-250"}],
        confidence=85,
    ),
    "DS-0026": TrivyRule(
        rule_id="docker.missing-healthcheck",
        title="No HEALTHCHECK instruction defined",
        problem="The Dockerfile has no HEALTHCHECK instruction (and doesn't inherit one from an earlier build stage).",
        impact=(
            "Without a HEALTHCHECK, container orchestration that doesn't already provide its own "
            "health monitoring (e.g. running the container directly, without a scheduler like "
            "Kubernetes) can't automatically detect and restart a container stuck in a bad but "
            "still-running state."
        ),
        recommendation=(
            "Add a HEALTHCHECK instruction, or confirm and document that the deployment target "
            "(e.g. Kubernetes liveness/readiness probes) already covers this."
        ),
        references=[{"standard": "CWE", "id": "CWE-16"}, {"standard": "OWASP-Top10", "id": "A02:2025"}],
        confidence=60,
    ),
}

# Docker's own documented legitimate uses for ADD (vs. COPY): fetching
# a URL, and auto-extracting a local archive. Anything else should be
# COPY. Verified at kickoff: hadolint's DL3020 uses the same principle
# (doesn't fire when ADD is used with an actual .tar.gz archive).
ARCHIVE_EXTENSIONS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")

CUSTOM_RULES: list[CustomRule] = [
    CustomRule(
        rule_id="docker.apt-upgrade",
        title="Dockerfile runs a full package upgrade during build",
        pattern=re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*upgrade\b", re.IGNORECASE),
        problem="A RUN instruction executes 'apt-get upgrade' (or 'apt upgrade') during the image build.",
        impact=(
            "This makes the build non-reproducible — the exact package versions installed depend on "
            "whatever is current in the package mirror at build time, not what was tested. It also "
            "means a compromised or unexpectedly-updated mirror package could be pulled into every "
            "future build silently."
        ),
        recommendation=(
            "Pin exact package versions in the install command instead of upgrading everything, or "
            "rebuild from an updated, re-verified base image instead."
        ),
        references=[{"standard": "CWE", "id": "CWE-1357"}, {"standard": "OWASP-Top10", "id": "A03:2025"}],
        severity="Medium",
        confidence=80,
        join_continuations=True,
    ),
    CustomRule(
        rule_id="docker.curl-pipe-shell",
        title="Remote script piped directly into a shell",
        pattern=re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:[\w./-]+\s+)*\b(?:sh|bash|zsh|ash)\b", re.IGNORECASE),
        problem="A RUN instruction downloads a remote script and pipes it directly into a shell without any integrity verification.",
        impact=(
            "If the remote server, DNS, or network path is ever compromised (or the script changes "
            "maliciously after the Dockerfile was written), the build executes arbitrary "
            "attacker-controlled code with no verification step to catch it."
        ),
        recommendation=(
            "Download the script to a file first, verify its checksum/signature against a known-good "
            "value, and only then execute it — or vendor a pinned copy of the script instead of "
            "fetching it at build time."
        ),
        references=[{"standard": "CWE", "id": "CWE-494"}, {"standard": "OWASP-Top10", "id": "A08:2025"}],
        severity="High",
        confidence=85,
        join_continuations=True,
    ),
    CustomRule(
        rule_id="docker.add-instead-of-copy",
        title="ADD used where COPY would be safer/clearer",
        pattern=re.compile(r"^\s*ADD\s+(\S+)\s+(\S+)", re.IGNORECASE | re.MULTILINE),
        problem="An ADD instruction is used with a source that is neither a URL nor a recognized archive.",
        impact=(
            "ADD's implicit behaviors (auto-extracting archives, fetching URLs) are easy to trigger "
            "by accident and make a Dockerfile's behavior less predictable than COPY's — e.g. a "
            "future filename change to something with an archive-like extension would silently start "
            "auto-extracting."
        ),
        recommendation=(
            "Use COPY instead of ADD for plain local files/directories; reserve ADD only for its two "
            "documented special cases (URL fetch, local archive auto-extraction)."
        ),
        references=[{"standard": "CWE", "id": "CWE-16"}, {"standard": "OWASP-Top10", "id": "A02:2025"}],
        severity="Low",
        confidence=75,
        join_continuations=False,
    ),
]
