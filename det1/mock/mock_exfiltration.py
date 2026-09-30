"""Mock T-f (Exfiltration / Asymmetric Outbound Volume) detector simulating IsolationForest / One-Class SVM."""

from typing import Dict, Any
from schemas.features import FeatureVector
from schemas.threats import ThreatClass, DetectorFamily
from det1.base import BaseDetector, ECDFCalibrator


class MockExfiltrationDetector(BaseDetector):
    """Simulates IsolationForest/One-Class SVM scoring outbound transfer deviations against baseline."""

    def __init__(
        self,
        detector_id: str = "mock_det1a_exfil_iforest",
        model_version: str = "1.0.0-mock",
        alert_threshold: float = 0.50,
    ):
        # Empirical percentile calibrator for anomaly scores
        calibrator = ECDFCalibrator([-0.5, -0.2, 0.0, 0.2, 0.4, 0.55, 0.70, 0.85, 0.95])
        super().__init__(
            detector_id=detector_id,
            detector_family=DetectorFamily.DET1A_ANOMALY,
            threat_class=ThreatClass.T_F_EXFILTRATION,
            calibrator=calibrator,
            model_version=model_version,
            shared_evidence_domain="asymmetric_transfer",
            alert_threshold=alert_threshold,
        )

    def predict(self, features: FeatureVector) -> float:
        score = 0.0

        # Asymmetric ratio (outbound vs inbound)
        if features.out_to_in_byte_ratio > 20.0:
            score += 0.45
        elif features.out_to_in_byte_ratio > 5.0:
            score += 0.20

        # Volume deviation z-score against entity profile
        if features.volume_deviation_from_baseline > 3.5:
            score += 0.45
        elif features.volume_deviation_from_baseline > 2.0:
            score += 0.25

        # Raw volume threshold (e.g. > 10MB in window)
        if features.outbound_bytes > 10 * 1024 * 1024:
            score += 0.25
        elif features.outbound_bytes > 2 * 1024 * 1024:
            score += 0.10

        return min(1.0, score)

    def extract_evidence(self, features: FeatureVector, raw_score: float) -> Dict[str, Any]:
        return {
            "outbound_bytes": features.outbound_bytes,
            "inbound_bytes": features.inbound_bytes,
            "out_to_in_byte_ratio": round(features.out_to_in_byte_ratio, 2),
            "volume_deviation_from_baseline": round(features.volume_deviation_from_baseline, 2),
            "transfer_character": "HEAVY_ASYMMETRIC_OUTFLOW" if raw_score >= 0.5 else "NORMAL_SYMMETRY",
        }
