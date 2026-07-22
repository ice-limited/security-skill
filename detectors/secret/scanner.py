"""Secret detection: pattern + entropy scanning over raw text content.

Artifact-type-agnostic by design (decided at the plan 006 kickoff) — a
secret looks the same whether it's sitting in a .env, a Dockerfile ENV,
or a Kubernetes Secret's plaintext data field, so this scans raw
file/text content uniformly rather than branching per format.
`artifactType` on each finding is set from the caller-supplied value,
not inferred here.

See plans/006-secret-detection-skill.md and
meetings/2026-07-22-1359-plan-006-kickoff.md in the
security-skill-workspace repo for design rationale, and rules.py for
the pattern catalog (adapted from gitleaks, MIT License).
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

from rules import RULES

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_SOURCE = {"name": "secret-detector", "version": "0.1.0"}

# Known placeholder/example values that would otherwise match a rule —
# grown as real false positives surface (decided at kickoff: start
# small, don't try to anticipate every example value in existence).
KNOWN_PLACEHOLDERS = {
    "AKIAIOSFODNN7EXAMPLE",  # AWS's own documentation example access key
}

_MIN_ENTROPY_BITS_PER_CHAR = 3.0
_MIN_ENTROPY_CHECK_LENGTH = 8


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_random(value: str) -> bool:
    return len(value) >= _MIN_ENTROPY_CHECK_LENGTH and _shannon_entropy(value) >= _MIN_ENTROPY_BITS_PER_CHAR


def _byte_offset(content: str, char_offset: int) -> int:
    # Python's re module gives character positions on a str, which only
    # equal byte positions for pure-ASCII content. Encode the prefix and
    # measure it to get the real byte offset, per 001's byte-range
    # location decision — deliberate, not a rounding-error-prone
    # shortcut (decided at the plan 006 kickoff).
    return len(content[:char_offset].encode("utf-8"))


def _line_number(content: str, char_offset: int) -> int:
    return content.count("\n", 0, char_offset) + 1


def _finding_id(rule_id: str, file: str, start_line: int, end_line: int, start_byte: int, end_byte: int) -> str:
    # Hash of ruleId + normalized location, per finding.schema.json's
    # findingId definition. Includes byte offsets (not just line range)
    # so two distinct secrets on the same line get distinct findingIds —
    # consistent with plan 004's dedup key, which was fixed for exactly
    # this reason (two different secrets on one line must not collapse).
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{start_byte}|{end_byte}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"secret-{digest}"


def scan_text(content: str, file: str, artifact_type: str = "source-code") -> list[dict]:
    """Scans raw text content for hardcoded secrets, returning a list of
    findings matching finding.schema.json. Does not read from disk —
    see scan_file() for that."""
    findings = []
    for rule in RULES:
        for match in rule.pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)

            if value in KNOWN_PLACEHOLDERS:
                continue
            if rule.requires_entropy_check and not _looks_random(value):
                continue

            start_char, end_char = match.start(), match.end()
            start_line = _line_number(content, start_char)
            end_line = _line_number(content, end_char)
            start_byte = _byte_offset(content, start_char)
            end_byte = _byte_offset(content, end_char)

            findings.append(
                {
                    "findingId": _finding_id(rule.rule_id, file, start_line, end_line, start_byte, end_byte),
                    "ruleId": rule.rule_id,
                    "subSkill": "secret",
                    "artifactType": artifact_type,
                    "title": rule.title,
                    "problem": rule.problem,
                    "impact": rule.impact,
                    "recommendation": rule.recommendation,
                    "references": rule.references,
                    "severity": "Critical",
                    "confidence": rule.confidence,
                    "location": {
                        "file": file,
                        "startLine": start_line,
                        "endLine": end_line,
                        "startByte": start_byte,
                        "endByte": end_byte,
                    },
                    "detectorSource": DETECTOR_SOURCE,
                    "suppressed": False,
                }
            )
    return _suppress_generic_overlaps(findings)


def _suppress_generic_overlaps(findings: list[dict]) -> list[dict]:
    # A specific rule (e.g. secret.aws-access-key) and the generic
    # catch-all (secret.generic-api-key) can both match the same
    # underlying secret when the value also happens to clear the
    # generic rule's entropy gate and sit near a suggestive keyword —
    # confirmed as a real duplicate-finding bug while testing plan 006
    # (an AWS key assigned to `aws_key = "..."` fired both rules). This
    # is overlap within this detector's own rule set, not the
    # cross-detector dedup plan 004 deliberately deferred — 006 owns
    # its whole rule set, so it's responsible for not contradicting
    # itself. Drop a generic-api-key finding whenever its byte range
    # overlaps a finding from any more specific rule in the same scan.
    specific_ranges = [
        (f["location"]["startByte"], f["location"]["endByte"]) for f in findings if f["ruleId"] != "secret.generic-api-key"
    ]
    result = []
    for f in findings:
        if f["ruleId"] == "secret.generic-api-key":
            loc = f["location"]
            if any(loc["startByte"] < s_end and s_start < loc["endByte"] for s_start, s_end in specific_ranges):
                continue
        result.append(f)
    return result


def scan_file(path: Path, artifact_type: str = "source-code") -> list[dict]:
    content = Path(path).read_text(encoding="utf-8")
    return scan_text(content, str(path), artifact_type)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan a file for hardcoded secrets.")
    parser.add_argument("file", type=Path)
    parser.add_argument("--artifact-type", default="source-code")
    args = parser.parse_args(argv)

    findings = scan_file(args.file, args.artifact_type)
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    # Reconfigured here, not inside main(), so tests that redirect
    # stdout/stderr to an io.StringIO (which has no .reconfigure()) can
    # still call main() directly. See plans/022-cross-platform-compatibility.md
    # and common/streams.py.
    reconfigure_streams()
    sys.exit(main())
