from metadata_risk_analyzer.analyzer import build_attack_scenarios, build_findings, score_to_level


def test_build_findings_scores_high_risk_metadata():
    metadata = {
        "gps_latitude": 39.7392,
        "gps_longitude": -104.9903,
        "DateTimeOriginal": "2026:04:22 10:15:00",
        "Model": "iPhone 15",
        "BodySerialNumber": "ABC12345",
    }

    findings, score = build_findings(metadata)

    assert score == 85
    assert len(findings) == 4
    assert score_to_level(score) == "Critical"


def test_attack_scenarios_include_location_and_timeline():
    metadata = {
        "gps_latitude": 40.0,
        "gps_longitude": -105.0,
        "DateTimeOriginal": "2026:04:22 10:15:00",
    }

    scenarios = build_attack_scenarios(metadata)
    titles = {scenario.title for scenario in scenarios}

    assert "Home location inference" in titles
    assert "Routine tracking" in titles


def test_no_major_findings_returns_low_risk_message():
    findings, score = build_findings({})

    assert score == 0
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert score_to_level(score) == "Low"
