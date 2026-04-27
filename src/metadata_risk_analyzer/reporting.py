from __future__ import annotations

import json

from .models import ImageReport


def render_text_report(report: ImageReport) -> str:
    from .fingerprint import device_class_label

    lines = [
        f"== {report.metadata.get('file_name', report.image_path)} ==",
        f"Risk score: {report.risk_score}/100 ({report.risk_level})",
    ]

    fp = report.device_fingerprint
    if fp.has_signal:
        lines.extend([
            "",
            "Device fingerprint:",
            f"- Device: {fp.display_label} ({device_class_label(fp.device_class)}, confidence: {fp.confidence})",
        ])
        if fp.os_software:
            lines.append(f"- Software: {fp.os_software}")
        if fp.lens:
            lines.append(f"- Lens: {fp.lens}")
        if fp.serial_numbers:
            for k, v in fp.serial_numbers.items():
                lines.append(f"- {k}: {v}")
        if fp.host_computer:
            lines.append(f"- HostComputer: {fp.host_computer}")
        if fp.unique_id:
            lines.append(f"- ImageUniqueID: {fp.unique_id}")

    lines.extend(["", "Findings:"])

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
