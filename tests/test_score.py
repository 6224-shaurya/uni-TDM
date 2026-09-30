"""Unit tests for SCORE engine and severity calculation."""

from schemas.threats import ThreatClass, SeverityLevel
from schemas.features import FeatureVector
from schemas.alert import RawImpactInputs
from corr_score.severity import ScoreEngine
from config.settings import EngineSettings, AssetRegistry, default_asset_registry


def test_score_critical_asset_elevates_severity():
    engine = ScoreEngine()
    features = FeatureVector(
        packets_per_sec=40000.0,
        syn_to_synack_ratio=30.0,
    )

    # 10.0.0.1 is registered as Tier 1 Domain Controller (criticality 2.0)
    sev_dc, audit_dc = engine.evaluate_severity(
        threat_class=ThreatClass.T_A_DDOS,
        fused_confidence=0.92,
        subject_key="10.0.0.1",
        features=features,
    )

    # 172.16.10.5 is registered as Tier 4 Guest (criticality 0.8)
    sev_guest, audit_guest = engine.evaluate_severity(
        threat_class=ThreatClass.T_A_DDOS,
        fused_confidence=0.92,
        subject_key="172.16.10.5",
        features=features,
    )

    assert audit_dc.asset_criticality > audit_guest.asset_criticality
    assert audit_dc.composite_score > audit_guest.composite_score
    assert sev_dc == SeverityLevel.CRITICAL
    # Raw metrics audit is preserved
    assert "packets_per_sec" in audit_dc.raw_metrics
    assert audit_dc.class_base_weight == 0.85


def test_score_exfiltration_weight():
    engine = ScoreEngine()
    exfil_features = FeatureVector(
        outbound_bytes=100 * 1024 * 1024,
        out_to_in_byte_ratio=40.0,
    )

    sev, audit = engine.evaluate_severity(
        threat_class=ThreatClass.T_F_EXFILTRATION,
        fused_confidence=0.88,
        subject_key="10.0.0.2",  # Tier 1 DB
        features=exfil_features,
    )

    assert audit.class_base_weight == 0.95
    assert sev in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
    assert audit.observed_impact_magnitude > 0.5
