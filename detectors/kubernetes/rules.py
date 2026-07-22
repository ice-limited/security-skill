"""Kubernetes workload-hardening rule catalog.

All 8 checklist items from CONTEXT.md §7 are detected by Trivy's
`config` scan mode (github.com/aquasecurity/trivy, Apache-2.0) — the
same tool and scan mode 009 already wraps for Dockerfiles. Verified for
real at the plan 010 kickoff (and re-verified against a synthetic
Deployment manifest and a real `helm create`-generated chart at
implementation) that Trivy covers every item out of the box, with real
line-precise locations, and needs **no custom rules** — unlike 009,
which needed 3 hand-written rules for gaps neither Trivy nor Hadolint
covered.

`readOnlyRootFilesystem`/CPU-limit/memory-limit are each split into
their own rule_id (`kubernetes.missing-cpu-limit` /
`kubernetes.missing-memory-limit`) rather than one merged
"missing-resource-limits" rule_id, even though the original CONTEXT.md
checklist groups them as one line item — Trivy itself reports CPU and
memory limits as two independent checks (KSV-0011, KSV-0018), each
capable of firing independently (a container can have one limit set
and not the other), so collapsing them into one rule_id would lose
real, actionable specificity.

CWE-668 ("Exposure of Resource to Wrong Sphere") is reused for all
three host-namespace-sharing checks (hostNetwork/hostPID/hostPath) —
each shares a host-owned resource (network namespace, PID namespace,
filesystem path) with the container's control sphere, exactly what
CWE-668 describes. CWE-250 ("Execution with Unnecessary Privileges") is
reused for privileged/root-user, matching 009's own
docker.root-user precedent (cited alone, no OWASP pairing — verified at
009's kickoff that A02:2025's official mapped-CWE list doesn't include
it). CWE-1357 ("Reliance on Insufficiently Trustworthy Component") is
reused for the unpinned `:latest` tag, matching 009's own
docker.unpinned-base-image precedent exactly (same underlying concern:
a mutable reference standing in for an immutable one). CWE-400
("Uncontrolled Resource Consumption") is newly added for missing
resource limits — verified at implementation that it does NOT appear
in OWASP's official mapped-CWE lists for A02:2025, A06:2025, or
A10:2025 (all three checked directly against owasp.org), so it's cited
alone, no OWASP pairing, same as CWE-250's situation. CWE-732
("Incorrect Permission Assignment for Critical Resource") is newly
added for the writable root filesystem check — verified to be one of
A01:2025's officially mapped CWEs (fetched directly from owasp.org),
so it's cited together with OWASP A01:2025.

See plans/010-kubernetes-skill.md and
meetings/2026-07-22-2000-plan-010-kickoff.md in the
security-skill-workspace repo for design rationale.
"""

from __future__ import annotations

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


_HOST_NAMESPACE_REFS = [{"standard": "CWE", "id": "CWE-668"}, {"standard": "OWASP-Top10", "id": "A01:2025"}]
_UNNECESSARY_PRIVILEGE_REFS = [{"standard": "CWE", "id": "CWE-250"}]
_UNPINNED_TAG_REFS = [{"standard": "CWE", "id": "CWE-1357"}, {"standard": "OWASP-Top10", "id": "A03:2025"}]
_RESOURCE_CONSUMPTION_REFS = [{"standard": "CWE", "id": "CWE-400"}]
_PERMISSION_ASSIGNMENT_REFS = [{"standard": "CWE", "id": "CWE-732"}, {"standard": "OWASP-Top10", "id": "A01:2025"}]

TRIVY_RULES: dict[str, TrivyRule] = {
    "KSV-0009": TrivyRule(
        rule_id="kubernetes.host-network-access",
        title="Container has access to the host's network namespace (hostNetwork: true)",
        problem=(
            "The pod spec sets `hostNetwork: true`, giving every container in the pod direct access to the "
            "host's network interfaces and loopback, bypassing Kubernetes' network namespace isolation."
        ),
        impact=(
            "A compromised container can sniff traffic on the host network, reach services bound to localhost "
            "on the node (often unauthenticated, e.g. the kubelet's own API), and pivot to other pods/services "
            "reachable from the node itself — an escape from the pod's intended network boundary."
        ),
        recommendation=(
            "Remove `hostNetwork: true` unless the workload has a specific, documented need for host networking "
            "(e.g. a CNI plugin or node-level monitoring agent); use a Service/Ingress for normal inter-pod "
            "communication instead."
        ),
        references=_HOST_NAMESPACE_REFS,
        confidence=90,
    ),
    "KSV-0010": TrivyRule(
        rule_id="kubernetes.host-pid-access",
        title="Container has access to the host's process namespace (hostPID: true)",
        problem=(
            "The pod spec sets `hostPID: true`, giving containers visibility into (and, combined with other "
            "permissions, potential control over) all processes running on the host, not just their own "
            "container's."
        ),
        impact=(
            "A compromised container can enumerate host processes, read process memory/environment via /proc "
            "for other workloads or host processes, and — combined with sufficient privileges — signal or "
            "trace host processes, escaping the container's process isolation."
        ),
        recommendation="Remove `hostPID: true` unless the workload has a specific, documented need for it.",
        references=_HOST_NAMESPACE_REFS,
        confidence=90,
    ),
    "KSV-0017": TrivyRule(
        rule_id="kubernetes.privileged-container",
        title="Container runs in privileged mode",
        problem=(
            "The container's securityContext sets `privileged: true`, disabling nearly all of the kernel-level "
            "isolation Linux namespaces/cgroups/capabilities normally provide (device access, capabilities, "
            "seccomp, and AppArmor are all effectively bypassed)."
        ),
        impact=(
            "Trivial container-to-host escape: a privileged container can mount the host's filesystem, load "
            "kernel modules, and interact with host devices directly, giving an attacker who compromises the "
            "container root-equivalent control of the node."
        ),
        recommendation=(
            "Remove `privileged: true`; grant only the specific Linux capabilities the workload actually needs "
            "via `securityContext.capabilities.add`."
        ),
        references=_UNNECESSARY_PRIVILEGE_REFS,
        confidence=90,
    ),
    "KSV-0023": TrivyRule(
        rule_id="kubernetes.hostpath-volume",
        title="Pod mounts a hostPath volume",
        problem=(
            "The pod mounts a `hostPath` volume, giving the container read (or read-write) access to a path on "
            "the underlying node's filesystem."
        ),
        impact=(
            "Depending on the path mounted, a compromised container can read sensitive host files (credentials, "
            "kubelet certificates), modify files that affect the host or other pods, or — if the mounted path "
            "is broad enough — achieve full host compromise."
        ),
        recommendation=(
            "Avoid hostPath volumes; use a PersistentVolumeClaim, ConfigMap, or Secret instead. If unavoidable, "
            "mount the narrowest possible path, read-only."
        ),
        references=_HOST_NAMESPACE_REFS,
        confidence=85,
    ),
    "KSV-0012": TrivyRule(
        rule_id="kubernetes.root-user",
        title="Container runs as the root user",
        problem=(
            "The container runs as UID 0 (root) — either `runAsUser: 0` is set explicitly, or no "
            "`runAsNonRoot`/`runAsUser` is set at all, so the image's own default (often root) applies."
        ),
        impact=(
            "If an attacker achieves code execution in the container, they have root inside it, which — "
            "combined with any container-to-host escape (a kernel vulnerability, a misconfigured hostPath or "
            "privileged setting) — gives them root on the host as well, far more impactful than a non-root "
            "breakout."
        ),
        recommendation=(
            "Set `securityContext.runAsNonRoot: true` and `runAsUser` to a non-zero UID, or use an image built "
            "to run as non-root by default."
        ),
        references=_UNNECESSARY_PRIVILEGE_REFS,
        confidence=80,
    ),
    "KSV-0013": TrivyRule(
        rule_id="kubernetes.unpinned-image-tag",
        title="Container image uses the mutable ':latest' tag",
        problem=(
            "The container image reference uses the `:latest` tag (or no tag at all, which defaults to "
            "`:latest`), rather than a specific, immutable version or digest."
        ),
        impact=(
            "The exact image content can change between deployments with no corresponding change to the "
            "manifest — a compromised or vulnerable upstream image can be silently pulled on the next pod "
            "restart or reschedule, and rollbacks/audits can't reliably reproduce what was actually running."
        ),
        recommendation=(
            "Pin to a specific version tag or, stronger, an image digest (`image@sha256:...`); reserve "
            "`:latest` for local development only."
        ),
        references=_UNPINNED_TAG_REFS,
        confidence=90,
    ),
    "KSV-0011": TrivyRule(
        rule_id="kubernetes.missing-cpu-limit",
        title="Container has no CPU limit set",
        problem="The container's `resources.limits.cpu` is not set, so it has no upper bound on CPU usage.",
        impact=(
            "A single misbehaving or compromised container can consume all CPU available on its node, starving "
            "every other workload scheduled there — a cluster-wide availability impact from one pod."
        ),
        recommendation="Set `resources.limits.cpu` to a value appropriate for the workload's expected peak usage.",
        references=_RESOURCE_CONSUMPTION_REFS,
        confidence=75,
    ),
    "KSV-0018": TrivyRule(
        rule_id="kubernetes.missing-memory-limit",
        title="Container has no memory limit set",
        problem="The container's `resources.limits.memory` is not set, so it has no upper bound on memory usage.",
        impact=(
            "A single misbehaving or compromised container can consume all memory available on its node, "
            "triggering the OOM killer against arbitrary other workloads (not necessarily the offending one) "
            "and destabilizing the whole node."
        ),
        recommendation=(
            "Set `resources.limits.memory` to a value appropriate for the workload's expected peak usage."
        ),
        references=_RESOURCE_CONSUMPTION_REFS,
        confidence=75,
    ),
    "KSV-0014": TrivyRule(
        rule_id="kubernetes.writable-root-filesystem",
        title="Container's root filesystem is writable",
        problem=(
            "The container's securityContext does not set `readOnlyRootFilesystem: true` (or sets it to "
            "false), leaving the container's root filesystem writable at runtime."
        ),
        impact=(
            "If an attacker achieves code execution, a writable root filesystem lets them modify or replace "
            "binaries/libraries, drop and persist additional tooling, and tamper with the running application "
            "— the container-image-is-immutable-at-runtime assumption doesn't actually hold."
        ),
        recommendation=(
            "Set `securityContext.readOnlyRootFilesystem: true`; mount an explicit writable `emptyDir` volume "
            "for the specific paths the application needs to write to (e.g. `/tmp`, cache directories)."
        ),
        references=_PERMISSION_ASSIGNMENT_REFS,
        confidence=80,
    ),
}
