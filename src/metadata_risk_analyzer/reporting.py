from __future__ import annotations

import json

from .models import ImageReport


def render_text_report(report: ImageReport) -> str:
    lines = [
        f"== {report.metadata.get('file_name', report.image_path)} ==",
        f"Risk score: {report.risk_score}/100 ({report.risk_level})",
        "",
        "Findings:",
    ]

    if report.findings:
        for finding in report.findings:
            lines.append(f"- {finding.title}: {finding.evidence}")
            lines.append(f"  Recommendation: {finding.recommendation}")
    else:
        lines.append("- No findings recorded.")

    lines.extend(["", "Attack scenarios:"])
    if report.attack_scenarios:
        for scenario in report.attack_scenarios:
            lines.append(f"- {scenario.title}: {scenario.description}")
    else:
        lines.append("- No attack scenarios recorded.")

    return "\n".join(lines)


def render_json_report(report: ImageReport) -> str:
    return json.dumps(report.to_dict(), indent=2)
