"""Action Layer: turns a decided-upon Finding (finding.schema.json)
into a Remediation (schema/remediation.schema.json) — a safety-tier
assignment, an actionable recommendation, and, only where a genuinely
mechanical transformation exists for that ruleId, a computed patch +
impact-of-the-fix narrative + pull-request draft content.

**Pure data generator, by design — decided at this plan's own
kickoff**: this module never writes to the filesystem, never runs
`git`/`gh`, and never calls any external API. The `patch`/
`pullRequestDraft` fields it produces are data describing a proposed
change; applying a patch or opening a PR from that data is the
invoking agent's job (or plan 016's, for the PR-opening/notification
half specifically) — see plans/015-action-layer-recommendations-autofix.md
and meetings/2026-07-23-1000-plan-015-kickoff.md in the
security-skill-workspace repo.

**v1 real-patch scope: `secret.*` (006) only.** One generic,
ruleId-agnostic redaction transformation (replace the finding's own
matched byte span with a placeholder) is mechanically safe across
every secret ruleId — this is the *only* sub-skill where a real patch
is generated in v1; every other finding gets a safety tier and
recommendation with no `patch` field, per the kickoff's own decision
not to fabricate a patch for ruleIds where no safe, generic
transformation actually exists (see CONTEXT.md §10.1 and this plan's
own kickoff note on the IAM worked example).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import sys
from pathlib import Path

from validate import validate_safety_tiers

ACTION_DIR = Path(__file__).parent

_common_dir = next(p for p in ACTION_DIR.resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "action-remediation-builder"

# Only secret.* gets a real computed patch in v1 — see module docstring.
_PATCH_ELIGIBLE_SUB_SKILLS = frozenset({"secret"})

_REDACTION_PLACEHOLDER = "REDACTED_SECRET"


class RemediationError(Exception):
    """Raised for invalid input (a malformed safety-tier config, or a
    Finding whose location doesn't actually match the file content it's
    supposedly found in) — fail loud rather than silently producing a
    Remediation that doesn't correspond to the real file."""


def load_safety_tiers(path: Path | None = None) -> dict:
    tiers_path = path if path is not None else ACTION_DIR / "safety_tiers.json"
    data = json.loads(tiers_path.read_text(encoding="utf-8"))
    errors = validate_safety_tiers(data)
    if errors:
        raise RemediationError(f"{tiers_path} is not a valid safety-tier table: {'; '.join(errors)}")
    return data


def safety_tier_for(rule_id: str, sub_skill: str, tiers: dict) -> str:
    """Looks up `rule_id` in `ruleOverrides` first; falls back to
    `subSkillDefaults[sub_skill]` — the fallback exists because 007
    (code-review) and most of 008 (dependency) generate ruleIds
    dynamically (from Semgrep check_ids / CVE IDs), so no fixed,
    exhaustive per-ruleId table is possible for them the way it is for
    006/009–014/023's static rule catalogs."""
    override = tiers["ruleOverrides"].get(rule_id)
    if override is not None:
        return override
    default = tiers["subSkillDefaults"].get(sub_skill)
    if default is None:
        raise RemediationError(f"no safety-tier default for subSkill {sub_skill!r} (ruleId {rule_id!r})")
    return default


def _remediation_id(finding_id: str, rule_id: str) -> str:
    digest = hashlib.sha256(f"{finding_id}|{rule_id}".encode("utf-8")).hexdigest()[:12]
    return f"remediation-{digest}"


def generate_secret_redaction_patch(finding: dict, file_content: str) -> dict:
    """Generates a redaction patch for one secret.* finding: replaces
    the exact matched byte span (from the finding's own location) with
    a fixed placeholder, and renders a unified diff of the resulting
    one-line (or few-line) change.

    Reads the matched text directly from `file_content` at the
    finding's `startByte`/`endByte` rather than trusting any value the
    caller might separately supply — the byte range *is* the source of
    truth for what's being redacted, per plan 001's own byte-range
    location design."""
    location = finding["location"]
    if "startByte" not in location or "endByte" not in location:
        raise RemediationError(f"finding {finding['findingId']} has no byte-range location, cannot generate a patch")

    encoded = file_content.encode("utf-8")
    start_byte, end_byte = location["startByte"], location["endByte"]
    if not (0 <= start_byte <= end_byte <= len(encoded)):
        raise RemediationError(
            f"finding {finding['findingId']}'s byte range ({start_byte}, {end_byte}) doesn't fit the given file content "
            f"({len(encoded)} bytes) — file content doesn't match what was scanned"
        )

    original_text = encoded[start_byte:end_byte].decode("utf-8")
    new_encoded = encoded[:start_byte] + _REDACTION_PLACEHOLDER.encode("utf-8") + encoded[end_byte:]
    new_content = new_encoded.decode("utf-8")

    file_label = location["file"]
    unified_diff = "".join(
        difflib.unified_diff(
            file_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=file_label,
            tofile=file_label,
        )
    )

    return {
        "file": file_label,
        "location": location,
        "originalText": original_text,
        "replacementText": _REDACTION_PLACEHOLDER,
        "unifiedDiff": unified_diff,
    }


def _secret_pull_request_draft(finding: dict) -> dict:
    return {
        "title": f"Redact hardcoded secret ({finding['ruleId']}) in {finding['location']['file']}",
        "body": (
            f"Automated redaction for a `{finding['ruleId']}` finding at "
            f"`{finding['location']['file']}:{finding['location']['startLine']}`.\n\n"
            f"This replaces the leaked literal value with `{_REDACTION_PLACEHOLDER}` — it does **not** rotate the "
            "credential or move it to a secrets manager. Revoke/rotate the exposed credential and update the "
            "deployment to read it from a secrets manager before merging.\n"
        ),
    }


def _secret_impact_of_fix(finding: dict) -> str:
    return (
        f"Replacing the literal value at `{finding['location']['file']}:{finding['location']['startLine']}` with "
        f"`{_REDACTION_PLACEHOLDER}` removes the leaked secret from version control going forward, but does not by "
        "itself revoke the already-exposed credential (it may still be usable by anyone who already saw it, "
        "including in this file's git history) and does not supply a working replacement — whatever consumed this "
        "value will need it provided another way (e.g. an environment variable or secrets manager reference) "
        "before this change is deployed."
    )


def build_remediation(finding: dict, file_content: str | None = None, tiers: dict | None = None) -> dict:
    """Builds one Remediation record for one Finding.

    `file_content` is required (and used) only for sub-skills in
    `_PATCH_ELIGIBLE_SUB_SKILLS` — passing it for any other finding is
    harmless (it's simply not read), and omitting it for a
    patch-eligible finding raises rather than silently skipping the
    patch."""
    tiers = tiers if tiers is not None else load_safety_tiers()
    rule_id = finding["ruleId"]
    sub_skill = finding["subSkill"]
    tier = safety_tier_for(rule_id, sub_skill, tiers)

    remediation = {
        "remediationId": _remediation_id(finding["findingId"], rule_id),
        "findingId": finding["findingId"],
        "ruleId": rule_id,
        "safetyTier": tier,
        "recommendation": finding["recommendation"],
        "detectorSource": {"name": DETECTOR_NAME, "version": "1.0.0"},
    }

    if sub_skill in _PATCH_ELIGIBLE_SUB_SKILLS:
        if file_content is None:
            raise RemediationError(f"finding {finding['findingId']} (subSkill {sub_skill!r}) needs file_content to build its patch")
        if sub_skill == "secret":
            remediation["patch"] = generate_secret_redaction_patch(finding, file_content)
            remediation["impactOfFix"] = _secret_impact_of_fix(finding)
            remediation["pullRequestDraft"] = _secret_pull_request_draft(finding)

    return remediation


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Build a Remediation record from a Finding JSON file, and (for secret.* findings) the file it was found in.")
    parser.add_argument("finding_path", type=Path)
    parser.add_argument("--source-file", type=Path, default=None, help="The scanned file the finding's location refers to (required for secret.* findings)")
    args = parser.parse_args(argv)

    try:
        finding = json.loads(args.finding_path.read_text(encoding="utf-8"))
        file_content = args.source_file.read_text(encoding="utf-8") if args.source_file is not None else None
        remediation = build_remediation(finding, file_content=file_content)
    except (RemediationError, OSError, json.JSONDecodeError) as e:
        print(f"REMEDIATION ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
