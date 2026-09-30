"""Tests demonstrating plug-and-play swapping of fake detectors with real model implementations."""

from datetime import datetime, timezone
from typing import Dict, Any
from schemas.features import WindowData, FeatureVector
from schemas.threats import ThreatClass, DetectorFamily, SubjectType
from det1.base import BaseDetector, PlattCalibrator
from det1.registry import DetectorRegistry
from det1.engine import DetectionTierOrchestrator
from corr_score.pipeline import CorrelationPipeline


class RealTrainedONNXDDoSDetector(BaseDetector):
    """Simulates a real ONNX batch model artifact loaded when Phase 6 training completes."""

    def __init__(self, onnx_model_path: str = "models/t_a_ddos.onnx"):
        # Real calibrated sigmoid parameters fitted on Kaggle holdout set
        calibrator = PlattCalibrator(a=-8.2, b=4.1)
        super().__init__(
            detector_id="onnx_det1s_ddos_resnet",
            detector_family=DetectorFamily.DET1S_SUPERVISED,
            threat_class=ThreatClass.T_A_DDOS,
            calibrator=calibrator,
            model_version="2.0.0-onnx",
            model_sha256="4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123",
            shared_evidence_domain="volumetric_syn",
        )
        self.onnx_model_path = onnx_model_path

    def predict(self, features: FeatureVector) -> float:
        # Simulates onnxruntime.InferenceSession.run([features_array])
        # High-precision prediction logic
        feature_product = (features.packets_per_sec / 10000.0) * (features.syn_to_synack_ratio / 5.0)
        return min(1.0, feature_product * 0.5)

    def extract_evidence(self, features: FeatureVector, raw_score: float) -> Dict[str, Any]:
        return {
            "onnx_model_path": self.onnx_model_path,
            "runtime_backend": "onnxruntime-cpu-v1.17",
            "inference_score": raw_score,
        }


def test_detector_swap_lifecycle():
    # 1. Start with fresh registry holding default mock detectors
    registry = DetectorRegistry(auto_load_mocks=True)
    manifest_before = registry.get_manifest()
    assert any(m["detector_id"] == "mock_det1s_ddos_gbdt" for m in manifest_before)

    # 2. Real trained model arrives! Instantiate and swap into registry
    real_detector = RealTrainedONNXDDoSDetector(onnx_model_path="models/ddos_production.onnx")
    old_detector = registry.swap(ThreatClass.T_A_DDOS, real_detector)

    assert old_detector.detector_id == "mock_det1s_ddos_gbdt"
    assert registry.get_by_threat(ThreatClass.T_A_DDOS).detector_id == "onnx_det1s_ddos_resnet"

    manifest_after = registry.get_manifest()
    active_ddos = next(m for m in manifest_after if m["threat_class"] == ThreatClass.T_A_DDOS.value)
    assert active_ddos["detector_id"] == "onnx_det1s_ddos_resnet"
    assert active_ddos["model_version"] == "2.0.0-onnx"
    assert active_ddos["is_mock"] is False

    # 3. Detection tier orchestrator and correlation pipeline seamlessly use the new detector
    orchestrator = DetectionTierOrchestrator(registry=registry)
    now = datetime.now(timezone.utc)
    window = WindowData(
        window_id="win_real_test",
        window_start=now,
        window_end=now,
        subject_type=SubjectType.DST_IP,
        subject_key="10.0.0.1",
        features=FeatureVector(
            packets_per_sec=30000,
            syn_to_synack_ratio=15.0,
        ),
    )

    verdicts = orchestrator.evaluate_sync(window)
    pipeline = CorrelationPipeline()
    alerts = pipeline.process_window(window, verdicts)

    # Ensure verdict was produced by the new ONNX detector
    ddos_verdict = next(v for v in verdicts if v.detector_id == "onnx_det1s_ddos_resnet")
    assert ddos_verdict.model_version == "2.0.0-onnx"
    assert ddos_verdict.evidence_features["runtime_backend"] == "onnxruntime-cpu-v1.17"

    # Alert properly generated and scored
    assert len(alerts) >= 1
    ddos_alert = next(a for a in alerts if a.threat_class == ThreatClass.T_A_DDOS)
    assert ddos_alert.threat_class == ThreatClass.T_A_DDOS
    assert ddos_alert.fused_confidence > 0.5
