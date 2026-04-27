from __future__ import annotations

from .analyzer import build_attack_scenarios, build_findings, score_to_level
from .fingerprint import build_fingerprint
from .models import ImageReport


DEMO_SCENARIOS: dict[str, dict[str, object]] = {
    "gps": {
        "file_name": "demo-gps-photo.jpg",
        "gps_latitude": 39.7392,
        "gps_longitude": -104.9903,
        "DateTimeOriginal": "2026:04:22 08:14:00",
        "Model": "iPhone 15 Pro",
    },
    "routine": {
        "file_name": "demo-routine-photo.jpg",
        "DateTime": "2026:04:22 07:30:00",
        "DateTimeOriginal": "2026:04:22 07:28:00",
        "Make": "Apple",
        "Model": "iPhone 15",
        "Software": "iOS 18.3",
    },
    "serial": {
        "file_name": "demo-serial-camera.jpg",
        "Make": "Canon",
        "Model": "EOS R6",
        "LensModel": "RF24-70mm F2.8 L IS USM",
        "BodySerialNumber": "2389001472",
        "LensSerialNumber": "7714401882",
        "DateTimeOriginal": "2026:04:22 17:11:42",
        "ImageUniqueID": "IMG-UNIQUE-44719",
    },
}


def build_demo_report(scenario_name: str) -> ImageReport:
    metadata = DEMO_SCENARIOS[scenario_name].copy()
    findings, score = build_findings(metadata)
    scenarios = build_attack_scenarios(metadata)
    return ImageReport(
        image_path=str(metadata["file_name"]),
        metadata=metadata,
        findings=findings,
        attack_scenarios=scenarios,
        risk_score=min(score, 100),
        risk_level=score_to_level(score),
        device_fingerprint=build_fingerprint(metadata),
    )
