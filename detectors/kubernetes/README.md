# detectors/kubernetes/

Kubernetes workload hardening: `hostNetwork`, `hostPID`, `hostPath`,
privileged containers, root user, unpinned `:latest` image tags,
missing CPU/memory limits, writable root filesystems. See
`plans/010-kubernetes-skill.md` and
`meetings/2026-07-22-2000-plan-010-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Same tool as 009, no custom rules

Wraps Trivy's `config` scan mode (github.com/aquasecurity/trivy,
Apache-2.0) — the exact same tool and scan mode `detectors/docker/`
already wraps. Verified for real at the plan 010 kickoff, and
re-verified against a synthetic Deployment manifest and a real
`helm create`-generated chart at implementation, that Trivy covers
every item in CONTEXT.md §7's checklist natively, with real
line-precise locations. **No custom rules needed** — unlike 009, which
needed 3 hand-written rules for gaps neither Trivy nor Hadolint
covered.

The subprocess invocation, `Target`-path resolution, and
result-to-finding mapping logic live in `common/trivy_wrapper.py`,
shared with `detectors/docker/scanner.py` (009) — this module is a
thin wrapper over it (`import trivy_wrapper as _tw`): its own rule
catalog (`rules.py`) and the raw-YAML-vs-Helm `artifactType` mapping.
See `common/test_trivy_wrapper.py` for direct tests of the shared
logic itself.

## The 9 curated Trivy checks

The 8 CONTEXT.md §7 checklist items map to 9 Trivy check IDs — missing
resource limits splits into two independent rule_ids
(`kubernetes.missing-cpu-limit` / `kubernetes.missing-memory-limit`)
since Trivy itself reports CPU and memory limits as two independent
checks, each capable of firing on its own (a container can have one
limit set and not the other); collapsing them into one rule_id would
lose real, actionable specificity.

| ruleId | Trivy check ID | Checklist item |
|---|---|---|
| `kubernetes.host-network-access` | KSV-0009 | `hostNetwork` |
| `kubernetes.host-pid-access` | KSV-0010 | `hostPID` |
| `kubernetes.privileged-container` | KSV-0017 | `privileged` |
| `kubernetes.hostpath-volume` | KSV-0023 | `hostPath` |
| `kubernetes.root-user` | KSV-0012 | root user |
| `kubernetes.unpinned-image-tag` | KSV-0013 | `:latest` tag |
| `kubernetes.missing-cpu-limit` | KSV-0011 | missing CPU limit |
| `kubernetes.missing-memory-limit` | KSV-0018 | missing memory limit |
| `kubernetes.writable-root-filesystem` | KSV-0014 | `readOnlyRootFilesystem` |

Trivy reports **~23 Kubernetes checks total** — the 9 above plus others
(seccomp profiles, Linux capabilities, default namespace usage, image
registry trust, privilege escalation) that are equally legitimate
workload-hardening concerns, just not in the original checklist.
Deliberately not mapped in v1 (`map_trivy_misconfig` silently skips any
check ID not in `rules.TRIVY_RULES`, not an error) — good candidates
for a future scope expansion, not guessed at now.

## CWE/OWASP references — verified against cwe.mitre.org/owasp.org at implementation, not assumed

- **CWE-668** ("Exposure of Resource to Wrong Sphere") + **OWASP
  A01:2025** for all three host-namespace-sharing checks
  (hostNetwork/hostPID/hostPath) — each shares a host-owned resource
  with the container's control sphere, exactly what CWE-668 describes.
  Already seeded from an earlier plan; reused here.
- **CWE-250** ("Execution with Unnecessary Privileges"), cited alone
  (no OWASP pairing), for privileged-container and root-user — matches
  009's own `docker.root-user` precedent exactly (verified at 009's
  kickoff that A02:2025's official mapped-CWE list doesn't include it).
- **CWE-1357** ("Reliance on Insufficiently Trustworthy Component") +
  **OWASP A03:2025** for the unpinned `:latest` tag — matches 009's own
  `docker.unpinned-base-image` precedent exactly (same underlying
  concern: a mutable reference standing in for an immutable one).
- **CWE-400** ("Uncontrolled Resource Consumption"), cited alone, for
  both missing-limit checks — newly added to `knowledge/cwe.json` this
  plan. Verified directly against `owasp.org` that it does **not**
  appear in the officially mapped CWE lists for A02:2025 (Security
  Misconfiguration), A06:2025 (Insecure Design), or A10:2025
  (Mishandling of Exceptional Conditions) — the three most plausible
  candidates — so no OWASP pairing is claimed.
- **CWE-732** ("Incorrect Permission Assignment for Critical
  Resource") + **OWASP A01:2025** for the writable root filesystem
  check — newly added to `knowledge/cwe.json` this plan. Verified
  directly against `owasp.org/Top10/2025/A01_2025-Broken_Access_Control/`
  that CWE-732 is one of A01:2025's officially mapped CWEs.

## Helm charts — natively rendered and scanned, no `helm` CLI dependency

Verified for real against a genuine `helm create`-generated chart (not
hand-typed chart YAML — see `HelmChartTests` in `test_scanner.py`,
mirroring 008's "real, tool-generated fixtures" discipline): Trivy
renders and scans Helm charts on its own (`"Type": "helm"` in its JSON
output for the rendered template file), with zero need to shell out to
`helm template` or depend on the `helm` CLI at scan time. `scan_paths()`
just points at a chart directory the same way it points at a plain YAML
file or directory — no special-casing needed.

Each result's own Trivy `Type` field (`"kubernetes"` or `"helm"`) drives
this module's `artifactType` mapping directly
(`_ARTIFACT_TYPE_BY_TRIVY_TYPE`), so a finding from a rendered Helm
template is correctly tagged `artifactType: "helm"`, not
`"kubernetes-yaml"`.

## Known limitation: `kind: List` bundles are silently not scanned

Found during the "test plan 010" round, verified for real (not from
docs): Trivy's `config` scan mode does **not** recognize the
Kubernetes `kind: List` bundling pattern — a single document with an
`items:` array of resources, as opposed to `---`-separated
multi-document YAML (which **is** recognized correctly, with accurate
per-resource line numbers — see `test_multidoc_yaml_is_recognized_and_gives_correct_line_numbers`).
A `kind: List` file reports "0 config files detected" and produces no
`Results` at all, even when the embedded resources are clearly
vulnerable — indistinguishable from "scanned and found clean."
`test_kind_list_bundling_is_not_recognized_a_known_trivy_gap` locks in
this exact behavior so it reads as a documented gap, not a silent
regression; if a future Trivy version starts recognizing `kind: List`,
that test will start failing, which is the signal to revisit this.

Not fixed here — doing so would mean this module pre-splitting
`kind: List` bundles into separate synthetic documents before handing
them to Trivy, which is exactly the kind of custom preprocessing logic
the kickoff decided against (Trivy was chosen specifically because it
needed zero custom rules for this plan's scope). Worth a deliberate
scope decision if `kind: List` turns out to be a real pattern in
cpmatch's actual manifests, not something to silently bolt on.

## Usage

```python
from scanner import scan_file, scan_paths

findings = scan_paths(["path/to/manifests-or-chart"])   # invokes trivy once per path given
findings = scan_file(Path("deployment.yaml"))
```

```
python3 scanner.py path/to/manifests-or-chart
```

Requires the real `trivy` CLI on `PATH` (`brew install trivy`, a
prebuilt binary, or Scoop/WinGet on Windows) and network access for its
checks bundle on first run (cached locally after that). The Helm-chart
tests additionally require the real `helm` CLI on `PATH`, independently
skippable if absent. `test_scanner.py`'s subprocess-driving tests skip
themselves (not fail) if either tool isn't installed, but are never
mocked when they are (same discipline as every prior external-tool
wrapper here).

## Not this module's job

- File selection/exclusion — orchestration concern, same boundary as
  every other detector here.
- Helm chart authoring issues that aren't about the rendered manifest
  (chart structure, template logic correctness) — verified at 011's
  kickoff that neither Trivy nor Checkov actually has a distinct
  "chart authoring" check mode (both just render the chart and scan
  the output as Kubernetes manifests, exactly what this module already
  does), so 011 dropped Helm from its scope entirely rather than
  duplicating this module. Nothing currently owns Helm chart authoring
  as a distinct concern.
- The ~15 additional Trivy Kubernetes checks beyond this plan's curated
  8-item scope — good candidates for a future scope expansion, not
  included in v1.
- Secrets in Kubernetes manifests (e.g. plaintext values that should be
  `Secret` references) — 006's job.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v`
(macOS/Linux; see the top-level `security-skill/README.md`). Trivy has
full native Windows support (Scoop/WinGet); Helm also ships native
Windows binaries.
