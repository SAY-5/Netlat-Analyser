"""Timestamp normalization utilities for netlat."""

from __future__ import annotations

import datetime
from typing import Union


def ts_to_datetime(timestamp: float) -> datetime.datetime:
    """Convert a Unix epoch timestamp to a UTC datetime object."""
    return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)


def ts_to_iso(timestamp: float) -> str:
    """Convert a Unix epoch timestamp to an ISO-8601 string."""
    return ts_to_datetime(timestamp).isoformat()


def delta_ms(t1: float, t2: float) -> float:
    """Return the absolute time delta between two timestamps in milliseconds."""
    return abs(t2 - t1) * 1000.0


def normalize_ts(value: Union[float, int, datetime.datetime]) -> float:
    """Normalize various timestamp representations to a Unix epoch float.

    Accepts:
        float/int: treated as Unix epoch seconds.
        datetime: converted to Unix epoch seconds (must be timezone-aware or treated as UTC).
    """
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.timestamp()
    raise TypeError(f"Cannot normalize timestamp from type {type(value).__name__}")


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f}us"
    if seconds < 1.0:
        return f"{seconds * 1000:.2f}ms"
    if seconds < 60.0:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m{secs:.1f}s"
