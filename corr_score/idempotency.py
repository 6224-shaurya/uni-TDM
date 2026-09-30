"""Idempotency key generation for alerts and verdicts per SAD v2.0 §9.1."""

import hashlib
from datetime import datetime, timezone
from typing import Union
from schemas.threats import ThreatClass, SubjectType


def canonical_time_str(dt: Union[datetime, str]) -> str:
    """Formats datetime into deterministic ISO-8601 UTC string."""
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_idempotency_key(
    subject_type: Union[SubjectType, str],
    subject_key: str,
    threat_class: Union[ThreatClass, str],
    window_start: Union[datetime, str],
) -> str:
    """Computes SHA-256(subject_type || subject_key || threat_class || window_start).
    
    Guarantees that re-evaluating the same subject window for the same threat class
    produces the identical key, enabling deterministic deduplication in downstream STORE.
    """
    st_val = subject_type.value if isinstance(subject_type, SubjectType) else str(subject_type)
    tc_val = threat_class.value if isinstance(threat_class, ThreatClass) else str(threat_class)
    time_str = canonical_time_str(window_start)
    
    # Delimited canonical representation
    raw_payload = f"{st_val}||{subject_key.strip()}||{tc_val}||{time_str}"
    
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
