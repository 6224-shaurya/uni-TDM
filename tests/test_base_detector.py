"""Unit tests for BaseDetector contract, calibrators, and mock detector implementations."""

import pytest
from datetime import datetime, timezone
from schemas.features import WindowData, FeatureVector
from schemas.threats import ThreatClass, DetectorFamily, PriorityTag, SubjectType
from schemas.verdict import DetectionVerdict
from det1.base import (
    BaseDetector,
    PlattCalibrator,
    IsotonicCalibrator,
    ECDFCalibrator,
)
from det1.mock import (
    MockDDoSDetector,
    MockBeaconingDetector,
    MockDGADetector,
    MockEncryptedMalwareDetector,
    MockReconDetector,
    MockExfiltrationDetector,
)


def test_platt_calibrator():
    calibrator = PlattCalibrator(a=-2.0, b=0.0)
    # raw score 0 -> 1 / (1 + exp(0)) = 0.5
    assert pytest.approx(calibrator.calibrate(0.0), 0.01) == 0.5
    # positive raw score -> higher probability
    assert calibrator.calibrate(2.0) > 0.95
    # negative raw score -> lower probability
    assert calibrator.calibrate(-2.0) < 0.05


def test_isotonic_calibrator():
    breakpoints = [(0.0, 0.05), (0.5, 0.50), (1.0, 0.95)]
    calibrator = IsotonicCalibrator(breakpoints)
    assert calibrator.calibrate(0.0) == 0.05
    assert calibrator.calibrate(1.0) == 0.95
    assert pytest.approx(calibrator.calibrate(0.25), 0.01) == 0.275


def test_ecdf_calibrator():
    quantiles = [0.1, 0.3, 0.5, 0.7, 0.9]
    calibrator = ECDFCalibrator(quantiles)
    # score below lowest quantile -> 0.0
    assert calibrator.calibrate(0.05) == 0.0
    # score above highest quantile -> 1.0
    assert calibrator.calibrate(0.95) == 1.0
    # score between 0.3 and 0.5 -> 2 of 5 quantiles met -> 0.4
    assert calibrator.calibrate(0.4) == 0.4


def test_mock_detectors_conformance():
    """All 6 mock detectors must inherit BaseDetector and produce valid DetectionVerdicts."""
    detectors = [
        MockDDoSDetector(),
        MockBeaconingDetector(),
        MockDGADetector(),
        MockEncryptedMalwareDetector(),
        MockReconDetector(),
        MockExfiltrationDetector(),
    ]

    now = datetime.now(timezone.utc)
    dummy_window = WindowData(
        window_id="test_win_01",
        window_start=now,
        window_end=now,
        subject_type=SubjectType.SRC_IP,
        subject_key="192.168.1.100",
        features=FeatureVector(
            packets_per_sec=25000,
            syn_to_synack_ratio=15.0,
            source_ip_entropy=0.8,
            lomb_scargle_power=0.85,
            iat_jitter_mad_ms=12.0,
            autocorrelation_peak=0.82,
            qname="x88a29flkd019.evil-botnet.biz",
            qname_entropy=4.1,
            qname_length=32,
            nxdomain_rate=0.7,
            ja3_rarity_score=0.95,
            hll_distinct_dst_ports=120,
            hll_distinct_dst_hosts=40,
            outbound_bytes=150 * 1024 * 1024,
            out_to_in_byte_ratio=25.0,
            volume_deviation_from_baseline=4.2,
        ),
    )

    for det in detectors:
        assert isinstance(det, BaseDetector)
        assert isinstance(det.threat_class, ThreatClass)
        verdict = det.evaluate(dummy_window)
        assert isinstance(verdict, DetectionVerdict)
        assert verdict.detector_id == det.detector_id
        assert verdict.threat_class == det.threat_class
        assert 0.0 <= verdict.calibrated_confidence <= 1.0
        assert isinstance(verdict.evidence_features, dict)
        assert verdict.window_id == "test_win_01"
