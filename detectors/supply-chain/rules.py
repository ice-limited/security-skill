"""Supply chain finding text + reference catalog for this plan's
config-presence checks (missing image signing, missing SBOM
generation, missing SLSA provenance) and SBOM-validity check.

**No CWE cleanly covers any of these** — verified at implementation,
not assumed: "missing signing"/"missing SBOM"/"missing provenance" are
absence-of-a-practice findings, not weakness patterns CWE's own
taxonomy models (CWE describes flaws in what code *does*, not gaps in
what a pipeline *doesn't produce*). All four ruleIds here cite
**NIST-SSDF only** — matching this project's own established precedent
of citing a single standard alone when no second one cleanly fits
(e.g. 011's CWE-295, cited alone). References fetched directly from
NIST SSDF (SP 800-218) sources at this plan's implementation, not
guessed:
- **PS.2** ("Provide a Mechanism for Verifying Software Release
  Integrity") + **PS.2.1** ("Make integrity verification information
  available to software purchasers and consumers") — for missing image
  signing.
- **PS.3.2** ("Collect, maintain, and share provenance data for all
  components and other dependencies of each software release (e.g., in
  a software bill of materials [SBOM])") — for missing SBOM generation,
  missing SLSA provenance, and invalid/malformed SBOM content (all
  three are facets of the same underlying practice: producing and
  maintaining trustworthy provenance data).
"""

from __future__ import annotations

_SIGNING_REFS = [{"standard": "NIST-SSDF", "id": "PS.2"}, {"standard": "NIST-SSDF", "id": "PS.2.1"}]
_PROVENANCE_REFS = [{"standard": "NIST-SSDF", "id": "PS.3.2"}]
_BINARY_ARTIFACT_REFS = [{"standard": "CWE", "id": "CWE-1357"}, {"standard": "OWASP-Top10", "id": "A03:2025"}]
_MISSING_SAST_REFS = [{"standard": "NIST-SSDF", "id": "PW.7"}]

MISSING_IMAGE_SIGNING = {
    "rule_id": "supply-chain.missing-image-signing",
    "title": "Container image is built but never signed",
    "problem": (
        "This job builds a container image but no subsequent step in the same job signs it "
        "(e.g. with `cosign sign`)."
    ),
    "impact": (
        "Without a signature, nothing downstream (a Kubernetes admission controller, a deployment pipeline, a "
        "consumer pulling the image) can verify this image actually came from this pipeline and wasn't "
        "substituted or tampered with after the build."
    ),
    "recommendation": (
        "Add a signing step after the build (e.g. `cosign sign <image>`, ideally keyless via OIDC) so consumers "
        "can verify the image's provenance before trusting it."
    ),
    "references": _SIGNING_REFS,
    "severity": "Medium",
    "confidence": 55,
}

MISSING_SBOM_GENERATION = {
    "rule_id": "supply-chain.missing-sbom-generation",
    "title": "Container image is built but no SBOM is generated for it",
    "problem": (
        "This job builds a container image but no subsequent step in the same job generates "
        "a Software Bill of Materials for it (e.g. via `syft`, `cyclonedx`, `anchore/sbom-action`, or "
        "`cosign attest --type sbom`)."
    ),
    "impact": (
        "Without an SBOM, consumers of this image (and this project's own Dependency Skill, applied downstream) "
        "have no reliable, machine-readable record of what's actually inside it — package versions, licenses, "
        "and known-vulnerable components can't be assessed without one."
    ),
    "recommendation": (
        "Add an SBOM-generation step after the build (e.g. `syft <image> -o cyclonedx-json`, or "
        "`cosign attest --type sbom`) and publish/attach the resulting SBOM to the release."
    ),
    "references": _PROVENANCE_REFS,
    "severity": "Medium",
    "confidence": 55,
}

MISSING_SLSA_PROVENANCE = {
    "rule_id": "supply-chain.missing-slsa-provenance",
    "title": "Workflow builds an artifact but generates no SLSA provenance",
    "problem": (
        "This workflow builds a container image or artifact, but no job references the official SLSA GitHub "
        "Actions provenance generator (`slsa-framework/slsa-github-generator`) anywhere."
    ),
    "impact": (
        "Without SLSA provenance, there is no verifiable, tamper-evident record of *how* this artifact was "
        "built (source commit, builder identity, build parameters) — consumers can't distinguish a legitimately "
        "built artifact from one produced by a compromised or subverted pipeline."
    ),
    "recommendation": (
        "Add a provenance-generation job using `slsa-framework/slsa-github-generator`'s reusable workflow "
        "(container or generic artifact variant, matching this pipeline's build output), and publish the "
        "resulting provenance attestation alongside the artifact."
    ),
    "references": _PROVENANCE_REFS,
    "severity": "Medium",
    "confidence": 50,
}

BINARY_ARTIFACT_COMMITTED = {
    "rule_id": "supply-chain.binary-artifact-committed",
    "title": "Generated executable (binary) artifact committed to source control",
    "problem": "{detail}",
    "impact": (
        "A binary blob can't be reviewed the way source code can — its actual contents, and whether it matches "
        "what its own build process would have produced, can't be verified by reading it. It could be a stale, "
        "hand-modified, or maliciously substituted build output masquerading as source."
    ),
    "recommendation": (
        "Remove committed binaries from source control; build them from source as part of the pipeline instead, "
        "or store genuinely-needed pre-built artifacts in a package registry/artifact store with its own "
        "provenance tracking, not the source repo."
    ),
    "references": _BINARY_ARTIFACT_REFS,
    "severity": "Medium",
    "confidence": 70,
}

MISSING_SAST_TOOL = {
    "rule_id": "supply-chain.missing-sast-tool",
    "title": "No static analysis (SAST) tool detected in CI",
    "problem": "No CI configuration referencing a recognized static analysis tool (e.g. CodeQL, LGTM, SonarCloud) was found.",
    "impact": (
        "Without an automated static analysis step in CI, vulnerability classes this project's own Code Review "
        "sub-skill (and any other SAST tooling) would catch may only ever be found via manual review, if at all "
        "— a meta-level gap in the pipeline's own security posture, not a specific code vulnerability."
    ),
    "recommendation": "Add a SAST tool to CI (e.g. GitHub CodeQL, a SonarCloud/SonarQube scan, or this project's own Semgrep-based Code Review sub-skill) so every change is automatically screened.",
    "references": _MISSING_SAST_REFS,
    "severity": "Low",
    "confidence": 60,
}

INVALID_SBOM = {
    "rule_id": "supply-chain.invalid-sbom",
    "title": "SBOM file does not conform to its own declared format",
    "problem": "This file declares itself as a {sbom_format} SBOM but does not validate against the official {sbom_format} JSON Schema.",
    "impact": (
        "A malformed SBOM can't be reliably consumed by downstream tooling (vulnerability scanners, license "
        "compliance checks, procurement/compliance systems) — it may be silently skipped, partially parsed, or "
        "rejected outright, defeating the purpose of publishing one at all."
    ),
    "recommendation": "Regenerate the SBOM with a standards-compliant tool (e.g. `syft`, `cyclonedx-cli`) rather than hand-editing or hand-assembling it.",
    "references": _PROVENANCE_REFS,
    "severity": "Low",
    "confidence": 90,
}
