"""Tests for LogShield analysis functions."""

from src.models import LogEvent
from src.triage import (
    build_report,
    calculate_threat_score,
    find_failed_login_ips,
    threat_level,
)


def make_events():
    """Create sample events for testing."""
    return [
        LogEvent(
            "2026-09-11 10:00:00",
            "ERROR",
            "Failed login from 10.0.0.5",
            "10.0.0.5",
        ),
        LogEvent(
            "2026-09-11 10:00:01",
            "ERROR",
            "Failed login from 10.0.0.5",
            "10.0.0.5",
        ),
        LogEvent(
            "2026-09-11 10:00:02",
            "ERROR",
            "Failed login from 10.0.0.5",
            "10.0.0.5",
        ),
    ]


def test_failed_login_detection():
    """Check repeated failed login detection."""
    result = find_failed_login_ips(make_events())

    assert result == {"10.0.0.5": 3}


def test_threat_level():
    """Check threat level thresholds."""
    assert threat_level(0) == "LOW"
    assert threat_level(3) == "MEDIUM"
    assert threat_level(6) == "HIGH"


def test_report():
    """Check report generation."""
    report = build_report(make_events())

    assert report["total_events"] == 3
    assert report["threat_level"] == "HIGH"


def test_score():
    """Check threat score calculation."""
    suspicious = {"10.0.0.5": 3}

    score = calculate_threat_score(
        make_events(),
        suspicious,
    )

    assert score == 6