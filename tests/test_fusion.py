"""Unit tests for Noisy-OR fusion with shared-evidence discount."""

from datetime import datetime, timezone
from schemas.verdict import DetectionVerdict
from schemas.threats import ThreatClass, DetectorFamily, SubjectType
from corr_score.fusion import NoisyORFusionEngine


def _make_verdict(det_id: str, conf: float, evidence_domain: str) -> DetectionVerdict:
    now = datetime.now(timezone.utc)
    return DetectionVerdict(
        detector_id=det_id,
        detector_family=DetectorFamily.DET1S_SUPERVISED,
        threat_class=ThreatClass.T_A_DDOS,
        subject_type=SubjectType.SRC_IP,
        subject_key="10.0.0.5",
        window_id="win_test",
        window_start=now,
        window_end=now,
        raw_score=conf,
        calibrated_confidence=conf,
        shared_evidence_domain=evidence_domain,
    )


def test_fusion_single_verdict():
    engine = NoisyORFusionEngine()
    v1 = _make_verdict("det1", 0.75, "volumetric_syn")
    fused, audit = engine.fuse([v1])
    assert fused == 0.75


def test_fusion_independent_domains():
    """Different evidence domains fuse via standard Noisy-OR."""
    engine = NoisyORFusionEngine()
    # 0.6 in volumetric, 0.5 in dns
    v1 = _make_verdict("vol_det", 0.60, "volumetric_syn")
    v2 = _make_verdict("dns_det", 0.50, "dns_entropy")

    fused, audit = engine.fuse([v1, v2])
    # 1 - (1 - 0.6) * (1 - 0.5) = 1 - 0.4 * 0.5 = 1 - 0.2 = 0.80
    assert abs(fused - 0.80) < 0.01


def test_fusion_shared_evidence_discount():
    """Same evidence domain applies gamma discount to secondary redundant signal."""
    engine = NoisyORFusionEngine(default_discount=0.50)
    # DET0 fast SYN heuristic (0.80) and DET1 GBDT SYN model (0.70) share 'volumetric_syn'
    v1 = _make_verdict("det0_syn_fast", 0.80, "volumetric_syn")
    v2 = _make_verdict("det1_syn_gbdt", 0.70, "volumetric_syn")

    fused, audit = engine.fuse([v1, v2])

    # Unadjusted Noisy-OR would be: 1 - (1 - 0.8)(1 - 0.7) = 1 - 0.2 * 0.3 = 0.94
    # With 0.5 discount on secondary:
    # effective secondary = 0.70 * 0.50 = 0.35
    # fused = 1 - (1 - 0.80) * (1 - 0.35) = 1 - 0.20 * 0.65 = 1 - 0.13 = 0.87
    assert fused < 0.94
    assert abs(fused - 0.87) < 0.02
    assert audit["discount_factor_gamma"] == 0.50
