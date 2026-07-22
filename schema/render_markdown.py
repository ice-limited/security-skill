"""Render a ScanReport (scan-report.schema.json) to Markdown.

Primary use case: a PR comment. See plans/001-finding-schema-output.md in
the security-skill-workspace repo for design rationale.
"""

from __future__ import annotations

import json
import sys

from _common import SEVERITY_ORDER, format_location, format_references, group_by_severity


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Security Review — {report['repository']}")
    lines.append("")
    if report.get("branch") or report.get("commit"):
        meta = []
        if report.get("branch"):
            meta.append(f"branch `{report['branch']}`")
        if report.get("commit"):
            meta.append(f"commit `{report['commit']}`")
        lines.append(" · ".join(meta))
        lines.append("")

    summary = report["summary"]
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity} | {summary[severity.lower()]} |")
    lines.append(f"| **Total** | **{summary['total']}** |")
    lines.append("")

    groups = group_by_severity(report["findings"])
    for severity in SEVERITY_ORDER:
        findings = groups[severity]
        if not findings:
            continue
        lines.append(f"## {severity}")
        lines.append("")
        for finding in findings:
            suppressed_tag = " _(suppressed)_" if finding["suppressed"] else ""
            lines.append(f"### {finding['title']}{suppressed_tag}")
            lines.append("")
            lines.append(f"- **Location:** `{format_location(finding)}`")
            lines.append(f"- **Rule:** `{finding['ruleId']}`")
            lines.append(f"- **Confidence:** {finding['confidence']}%")
            lines.append(f"- **Reference:** {format_references(finding)}")
            lines.append("")
            lines.append(f"**Problem:** {finding['problem']}")
            lines.append("")
            lines.append(f"**Impact:** {finding['impact']}")
            lines.append("")
            lines.append(f"**Recommendation:** {finding['recommendation']}")
            lines.append("")
            if finding["suppressed"] and finding.get("suppressionReason"):
                lines.append(f"> Suppressed: {finding['suppressionReason']}")
                lines.append("")

    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":
    data = json.load(sys.stdin)
    sys.stdout.write(render_markdown(data))
