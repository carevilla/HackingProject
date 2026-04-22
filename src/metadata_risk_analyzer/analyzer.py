from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import AttackScenario, Finding, ImageReport


def analyze_image(image_path: str | Path) -> ImageReport:
    from .extractors import extract_image_metadata

    metadata = extract_image_metadata(image_path)
    findings, score = build_findings(metadata)
    scenarios = build_attack_scenarios(metadata)
    return ImageReport(
        image_path=str(Path(image_path)),
        metadata=metadata,
        findings=findings,
        attack_scenarios=scenarios,
        risk_score=min(score, 100),
        risk_level=score_to_level(score),
    )


def build_findings(metadata: dict[str, Any]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    score = 0

    if metadata.get("gps_latitude") is not None and metadata.get("gps_longitude") is not None:
        findings.append(
            Finding(
                category="location",
                severity="high",
                title="GPS coordinates found",
                evidence=(
                    f"Latitude {metadata['gps_latitude']}, "
                    f"longitude {metadata['gps_longitude']} are embedded in the image."
                ),
                recommendation="Remove geotags before sharing publicly.",
            )
        )
        score += 40

    timestamp_fields = [
        "DateTime",
        "DateTimeOriginal",
        "DateTimeDigitized",
    ]
    present_timestamps = [field for field in timestamp_fields if metadata.get(field)]
    if present_timestamps:
        findings.append(
            Finding(
                category="temporal",
                severity="medium",
                title="Capture timestamps found",
                evidence=f"Timestamp fields present: {', '.join(present_timestamps)}.",
                recommendation="Consider removing timestamps if posting publicly or anonymously.",
            )
        )
        score += 15

    fingerprint_fields = [
        "Make",
        "Model",
        "Software",
        "LensModel",
    ]
    present_fingerprint_fields = [field for field in fingerprint_fields if metadata.get(field)]
    if present_fingerprint_fields:
        findings.append(
            Finding(
                category="fingerprinting",
                severity="medium",
                title="Device fingerprinting indicators found",
                evidence=(
                    "These fields can help correlate images to the same device: "
                    + ", ".join(present_fingerprint_fields)
                    + "."
                ),
                recommendation="Strip device-identifying fields before sharing widely.",
            )
        )
        score += 10

    serial_fields = [
        "BodySerialNumber",
        "CameraSerialNumber",
        "LensSerialNumber",
    ]
    present_serial_fields = [field for field in serial_fields if metadata.get(field)]
    if present_serial_fields:
        findings.append(
            Finding(
                category="tracking",
                severity="high",
                title="Serial identifiers found",
                evidence="Unique serial-like metadata present: " + ", ".join(present_serial_fields) + ".",
                recommendation="Redact serial identifiers before publishing images.",
            )
        )
        score += 20

    identity_fields = [
        "Artist",
        "Copyright",
        "OwnerName",
        "HostComputer",
    ]
    present_identity_fields = [field for field in identity_fields if metadata.get(field)]
    if present_identity_fields:
        findings.append(
            Finding(
                category="identity",
                severity="medium",
                title="Potential identity leakage found",
                evidence="Personal or owner-related fields present: " + ", ".join(present_identity_fields) + ".",
                recommendation="Remove author or owner fields when anonymity matters.",
            )
        )
        score += 10

    correlation_fields = [
        "ImageUniqueID",
        "UniqueImageID",
    ]
    present_correlation_fields = [field for field in correlation_fields if metadata.get(field)]
    if present_correlation_fields:
        findings.append(
            Finding(
                category="correlation",
                severity="medium",
                title="Unique image identifiers found",
                evidence="Unique identifiers present: " + ", ".join(present_correlation_fields) + ".",
                recommendation="Remove unique IDs to reduce cross-platform linkability.",
            )
        )
        score += 10

    if not findings:
        findings.append(
            Finding(
                category="general",
                severity="low",
                title="No major privacy-heavy EXIF indicators found",
                evidence="The image did not expose the main fields covered by the first-pass analyzer.",
                recommendation="Review manually for other hidden metadata if the image is sensitive.",
            )
        )

    return findings, score


def build_attack_scenarios(metadata: dict[str, Any]) -> list[AttackScenario]:
    scenarios: list[AttackScenario] = []

    if metadata.get("gps_latitude") is not None and metadata.get("gps_longitude") is not None:
        scenarios.append(
            AttackScenario(
                title="Home location inference",
                description="An attacker can map the photo location and compare repeated uploads to infer home, work, school, or travel habits.",
            )
        )

    if any(metadata.get(field) for field in ("DateTime", "DateTimeOriginal", "DateTimeDigitized")):
        scenarios.append(
            AttackScenario(
                title="Routine tracking",
                description="Timestamps across multiple uploads can reconstruct a timeline of activity and reveal repeated patterns.",
            )
        )

    if any(metadata.get(field) for field in ("Make", "Model", "Software", "LensModel")):
        scenarios.append(
            AttackScenario(
                title="Device correlation",
                description="Device-specific metadata can help link multiple images to the same phone, camera, or editing workflow.",
            )
        )

    if any(metadata.get(field) for field in ("BodySerialNumber", "CameraSerialNumber", "LensSerialNumber")):
        scenarios.append(
            AttackScenario(
                title="Long-term serial tracking",
                description="Serial-like identifiers can uniquely associate content with a specific device over time.",
            )
        )

    if not scenarios:
        scenarios.append(
            AttackScenario(
                title="Low-confidence metadata exposure",
                description="No strong attack scenario was triggered by the current rules, but more advanced parsers could still uncover additional signals.",
            )
        )

    return scenarios


def score_to_level(score: int) -> str:
    capped = min(score, 100)
    if capped >= 80:
        return "Critical"
    if capped >= 60:
        return "High"
    if capped >= 30:
        return "Moderate"
    return "Low"
