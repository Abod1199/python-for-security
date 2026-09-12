"""Data models for LogShield."""


class LogEvent:
    """Store information about one security log event."""

    def __init__(self, timestamp, level, message, ip=None):
        self.timestamp = timestamp
        self.level = level
        self.message = message
        self.ip = ip

    def to_dict(self):
        """Convert the log event into a dictionary."""
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "message": self.message,
            "ip": self.ip,
        }