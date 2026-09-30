"""Unit tests for DET0 fast-path annotator."""

from datetime import datetime, timezone
from schemas.features import WindowData, FeatureVector
from schemas.threats import ThreatClass, DetectorFamily, PriorityTag, SubjectType
from det0.annotator import FastPathAnnotator


def test_det0_drops_nothing_on_benign_traffic():
    annotator = FastPathAnnotator()
    now = datetime.now(timezone.utc)
    benign_window = WindowData(
        window_id="win_benign",
        window_start=now,
        window_end=now,
        subject_type=SubjectType.SRC_IP,
        subject_key="192.168.1.15",
        features=FeatureVector(
            packets_per_sec=120.0,
            syn_count=10,
            syn_ack_count=10,
            syn_to_synack_ratio=1.0,
            qname="google.com",
            qname_entropy=2.1,
            qname_length=10,
            hll_distinct_dst_ports=2,
            outbound_bytes=50000,
            inbound_bytes=100000,
            out_to_in_byte_ratio=0.5,
        ),
    )

    verdict = annotator.annotate(benign_window)
    # Crucial property: drops nothing! Emits P3_NORMAL verdict
    assert verdict.detector_family == DetectorFamily.DET0_FAST_PATH
    assert verdict.priority_tag == PriorityTag.P3_NORMAL
    assert verdict.is_alert_worthy is False


def test_det0_triggers_p0_on_critical_syn_flood():
    annotator = FastPathAnnotator()
    now = datetime.now(timezone.utc)
    ddos_window = WindowData(
        window_id="win_ddos",
        window_start=now,
        window_end=now,
        subject_type=SubjectType.DST_IP,
        subject_key="10.0.0.1",
        features=FeatureVector(
            packets_per_sec=65000.0,
            syn_count=5000,
            syn_ack_count=0,
            syn_to_synack_ratio=5000.0,
        ),
    )

    verdict = annotator.annotate(ddos_window)
    assert verdict.priority_tag == PriorityTag.P0_BURST_CRITICAL
    assert verdict.threat_class == ThreatClass.T_A_DDOS
    assert verdict.is_alert_worthy is True
    assert verdict.calibrated_confidence >= 0.90


def test_det0_triggers_p1_on_rapid_scan():
    annotator = FastPathAnnotator()
    now = datetime.now(timezone.utc)
    scan_window = WindowData(
        window_id="win_scan",
        window_start=now,
        window_end=now,
        subject_type=SubjectType.SRC_IP,
        subject_key="192.168.1.88",
        features=FeatureVector(
            hll_distinct_dst_ports=650,
            fanout_rate_pps=300.0,
        ),
    )

    verdict = annotator.annotate(scan_window)
    assert verdict.priority_tag == PriorityTag.P1_SUSPICIOUS_HEURISTIC
    assert verdict.threat_class == ThreatClass.T_E_RECON_SCAN
    assert verdict.is_alert_worthy is True
