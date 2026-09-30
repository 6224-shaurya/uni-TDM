"""Integration tests for FastAPI backend endpoints."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from api.app import app
from schemas.threats import ThreatClass, SeverityLevel

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["active_detectors"] >= 6
    assert data["ledger_cryptographic_chain_valid"] is True


def test_list_detectors_endpoint():
    response = client.get("/api/v1/detectors")
    assert response.status_code == 200
    manifest = response.json()
    assert len(manifest) >= 6
    threat_classes = [m["threat_class"] for m in manifest]
    assert ThreatClass.T_A_DDOS.value in threat_classes
    assert ThreatClass.T_F_EXFILTRATION.value in threat_classes


def test_detect_endpoint_ddos_attack():
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        "window_id": "win_api_ddos_01",
        "window_start": now_iso,
        "window_end": now_iso,
        "subject_type": "dst_ip",
        "subject_key": "10.0.0.1",
        "capture_loss_pct": 0.05,
        "features": {
            "packets_per_sec": 60000.0,
            "syn_count": 8000,
            "syn_ack_count": 0,
            "syn_to_synack_ratio": 8000.0,
            "source_ip_entropy": 0.5,
        },
    }

    response = client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["window_id"] == "win_api_ddos_01"
    assert data["verdicts_count"] >= 7  # 1 DET0 + 6 DET1 detectors
    assert data["alerts_generated"] >= 1

    alert = data["alerts"][0]
    assert alert["threat_class"] == ThreatClass.T_A_DDOS.value
    assert alert["severity"] in [SeverityLevel.CRITICAL.value, SeverityLevel.HIGH.value]
    assert len(alert["idempotency_key"]) == 64
    assert alert["subject_key"] == "10.0.0.1"
    assert "raw_impact_inputs" in alert
    assert alert["raw_impact_inputs"]["class_base_weight"] == 0.85


def test_alerts_query_and_idempotency_dedup():
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        "window_id": "win_exfil_dedup",
        "window_start": now_iso,
        "window_end": now_iso,
        "subject_type": "src_ip",
        "subject_key": "10.0.0.2",
        "features": {
            "outbound_bytes": 200 * 1024 * 1024,
            "inbound_bytes": 1024 * 1024,
            "out_to_in_byte_ratio": 200.0,
            "volume_deviation_from_baseline": 4.5,
        },
    }

    # First post generates an alert
    r1 = client.post("/api/v1/detect", json=payload)
    assert r1.status_code == 200
    alert1 = r1.json()["alerts"][0]
    k1 = alert1["idempotency_key"]

    # Duplicate post with same subject & window_start -> exact same idempotency key
    r2 = client.post("/api/v1/detect", json=payload)
    assert r2.status_code == 200
    alert2 = r2.json()["alerts"][0]
    assert alert2["idempotency_key"] == k1

    # Query alerts endpoint
    r_query = client.get("/api/v1/alerts?subject_key=10.0.0.2")
    assert r_query.status_code == 200
    queried = r_query.json()
    assert len(queried) >= 1
    assert queried[0]["threat_class"] == ThreatClass.T_F_EXFILTRATION.value
