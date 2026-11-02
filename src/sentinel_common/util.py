"""Small helpers shared by all responders."""

import os
from datetime import datetime, timezone


def env_list(name):
    """Read a comma separated environment variable into a clean list."""
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_event_time(value):
    """Parse a CloudTrail eventTime such as 2026-11-01T12:00:00Z."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def seconds_since(event_time):
    """Seconds between the CloudTrail event time and now. Returns 0.0 if unparsable."""
    try:
        started = parse_event_time(event_time)
    except (ValueError, AttributeError):
        return 0.0
    return max(0.0, (datetime.now(timezone.utc) - started).total_seconds())
