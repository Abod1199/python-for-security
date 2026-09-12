"""Security analysis and threat scoring functions."""

from collections import Counter


def count_levels(events):
    """Count INFO, WARNING, and ERROR events."""
    counts = Counter(event.level for event in events)

    return {
        "INFO": counts.get("INFO", 0),
        "WARNING": counts.get("WARNING", 0),
        "ERROR": counts.get("ERROR", 0),
    }


def find_failed_login_ips(events, threshold=3):
    """Find IP addresses with repeated failed logins."""
    failed_logins = Counter()

    for event in events:
        if (
            event.level == "ERROR"
            and "failed login" in event.message.lower()
        ):
            if event.ip:
                failed_logins[event.ip] += 1

    return {
        ip: count
        for ip, count in failed_logins.items()
        if count >= threshold
    }


def calculate_threat_score(events, suspicious_ips):
    """Calculate a simple rule-based threat score."""
    score = 0

    warning_count = sum(
        1 for event in events if event.level == "WARNING"
    )

    error_count = sum(
        1 for event in events if event.level == "ERROR"
    )

    score += warning_count * 2
    score += error_count
    score += len(suspicious_ips) * 3

    return score


def threat_level(score):
    """Convert a score into a threat level."""
    if score >= 6:
        return "HIGH"

    if score >= 3:
        return "MEDIUM"

    return "LOW"


def build_report(events):
    """Build the final security triage report."""
    level_counts = count_levels(events)

    suspicious_ips = find_failed_login_ips(events)

    score = calculate_threat_score(
        events,
        suspicious_ips,
    )

    return {
        "total_events": len(events),
        "log_levels": level_counts,
        "suspicious_ips": suspicious_ips,
        "threat_score": score,
        "threat_level": threat_level(score),
    }