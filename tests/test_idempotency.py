"""Unit tests for SHA-256 idempotency key generation."""

from datetime import datetime, timezone
from corr_score.idempotency import generate_idempotency_key
from schemas.threats import ThreatClass, SubjectType


def test_idempotency_key_deterministic():
    dt = datetime(2026, 9, 29, 18, 0, 0, tzinfo=timezone.utc)
    key1 = generate_idempotency_key(
        subject_type=SubjectType.SRC_IP,
        subject_key="192.168.1.100",
        threat_class=ThreatClass.T_A_DDOS,
        window_start=dt,
    )
    key2 = generate_idempotency_key(
        subject_type="src_ip",
        subject_key="192.168.1.100",
        threat_class="T-a:DDoS",
        window_start=dt,
    )
    assert key1 == key2
    assert len(key1) == 64  # SHA-256 hex string


def test_idempotency_key_sensitivity():
    dt1 = datetime(2026, 9, 29, 18, 0, 0, tzinfo=timezone.utc)
    dt2 = datetime(2026, 9, 29, 18, 0, 1, tzinfo=timezone.utc)

    k1 = generate_idempotency_key(SubjectType.SRC_IP, "192.168.1.1", ThreatClass.T_A_DDOS, dt1)
    k2 = generate_idempotency_key(SubjectType.SRC_IP, "192.168.1.2", ThreatClass.T_A_DDOS, dt1)
    k3 = generate_idempotency_key(SubjectType.SRC_IP, "192.168.1.1", ThreatClass.T_B_BEACONING, dt1)
    k4 = generate_idempotency_key(SubjectType.SRC_IP, "192.168.1.1", ThreatClass.T_A_DDOS, dt2)

    # All distinct tuples must have distinct hashes
    assert len({k1, k2, k3, k4}) == 4
