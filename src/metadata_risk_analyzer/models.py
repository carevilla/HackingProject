from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .fingerprint import DeviceFingerprint


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    evidence: str
    recommendation: str


@dataclass
class AttackScenario:
    title: str
    description: str


@dataclass
class ImageReport:
    image_path: str
    metadata: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    attack_scenarios: list[AttackScenario] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low"
    device_fingerprint: DeviceFingerprint = field(default_factory=DeviceFingerprint)

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_path": self.image_path,
            "metadata": self.metadata,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": [
                {
                    "category": finding.category,
                    "severity": finding.severity,
                    "title": finding.title,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                }
                for finding in self.findings
            ],
            "attack_scenarios": [
                {
                    "title": scenario.title,
                    "description": scenario.description,
                }
                for scenario in self.attack_scenarios
            ],
            "device_fingerprint": self.device_fingerprint.to_dict(),
        }
