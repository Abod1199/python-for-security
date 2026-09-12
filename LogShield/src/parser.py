"""Functions for reading and parsing security logs."""

import re

from .models import LogEvent


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<level>INFO|WARNING|ERROR) "
    r"(?P<message>.*)$"
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def parse_line(line):
    """Parse one log line into a LogEvent object."""
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    message = match.group("message")

    ip_match = IP_PATTERN.search(message)
    ip = ip_match.group(0) if ip_match else None

    return LogEvent(
        timestamp=match.group("timestamp"),
        level=match.group("level"),
        message=message,
        ip=ip,
    )


def load_events(path):
    """Read the log file and return parsed events."""
    events = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_line(line)

            if event is not None:
                events.append(event)

    return events