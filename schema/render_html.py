"""Render a ScanReport (scan-report.schema.json) to a standalone HTML report.

Self-contained (inline CSS, no external resources) so it works as a CI
artifact or offline file. See plans/001-finding-schema-output.md in the
security-skill-workspace repo for design rationale.
"""

from __future__ import annotations

import json
import sys
from html import escape

from _common import SEVERITY_ORDER, format_location, group_by_severity

_SEVERITY_COLOR = {
    "Critical": "#7f1d1d",
    "High": "#b91c1c",
    "Medium": "#b45309",
    "Low": "#1d4ed8",
    "Info": "#4b5563",
}

_STYLE = """
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 900px; line-height: 1.5; color: #1f2937; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.25rem; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #e5e7eb; padding: 0.4rem 0.8rem; text-align: left; }
.finding { border: 1px solid #e5e7eb; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
.finding h3 { margin-top: 0; }
.badge { display: inline-block; color: white; border-radius: 4px; padding: 0.1rem 0.5rem; font-size: 0.8rem; font-weight: 600; }
.meta { color: #6b7280; font-size: 0.9rem; }
.suppressed { opacity: 0.6; }
"""


def _finding_html(finding: dict) -> str:
    color = _SEVERITY_COLOR[finding["severity"]]
    suppressed_class = " suppressed" if finding["suppressed"] else ""
    refs = ", ".join(
        (
            f'<a href="{escape(ref["url"])}">{escape(ref["standard"])} {escape(ref["id"])}</a>'
            if ref.get("url")
            else f'{escape(ref["standard"])} {escape(ref["id"])}'
        )
        for ref in finding["references"]
    )
    suppression_note = ""
    if finding["suppressed"] and finding.get("suppressionReason"):
        suppression_note = f'<p class="meta">Suppressed: {escape(finding["suppressionReason"])}</p>'

    return f"""
<div class="finding{suppressed_class}">
  <span class="badge" style="background:{color}">{escape(finding['severity'])}</span>
  <h3>{escape(finding['title'])}</h3>
  <p class="meta">
    <code>{escape(format_location(finding))}</code> ·
    rule <code>{escape(finding['ruleId'])}</code> ·
    confidence {finding['confidence']}% ·
    {refs}
  </p>
  <p><strong>Problem:</strong> {escape(finding['problem'])}</p>
  <p><strong>Impact:</strong> {escape(finding['impact'])}</p>
  <p><strong>Recommendation:</strong> {escape(finding['recommendation'])}</p>
  {suppression_note}
</div>"""


def render_html(report: dict) -> str:
    summary = report["summary"]
    summary_rows = "\n".join(
        f"<tr><td>{severity}</td><td>{summary[severity.lower()]}</td></tr>"
        for severity in SEVERITY_ORDER
    )

    meta_parts = []
    if report.get("branch"):
        meta_parts.append(f"branch <code>{escape(report['branch'])}</code>")
    if report.get("commit"):
        meta_parts.append(f"commit <code>{escape(report['commit'])}</code>")
    meta_line = f"<p class=\"meta\">{' · '.join(meta_parts)}</p>" if meta_parts else ""

    groups = group_by_severity(report["findings"])
    sections = []
    for severity in SEVERITY_ORDER:
        findings = groups[severity]
        if not findings:
            continue
        findings_html = "\n".join(_finding_html(f) for f in findings)
        sections.append(f"<h2>{severity}</h2>{findings_html}")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Review — {escape(report['repository'])}</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>Security Review — {escape(report['repository'])}</h1>
{meta_line}
<table>
<thead><tr><th>Severity</th><th>Count</th></tr></thead>
<tbody>
{summary_rows}
<tr><td><strong>Total</strong></td><td><strong>{summary['total']}</strong></td></tr>
</tbody>
</table>
{''.join(sections)}
</body>
</html>
"""


if __name__ == "__main__":
    data = json.load(sys.stdin)
    sys.stdout.write(render_html(data))
