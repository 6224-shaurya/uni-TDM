"""Mock T-a (DDoS / Volumetric Flood) detector simulating GBDT classification."""

from typing import Dict, Any
from schemas.features import FeatureVector
from schemas.threats import ThreatClass, DetectorFamily
from det1.base import BaseDetector, IsotonicCalibrator


class MockDDoSDetector(BaseDetector):
    """Simulates GBDT model predicting DDoS SYN/UDP/reflection flood attacks."""

    def __init__(
        self,
        detector_id: str = "mock_det1s_ddos_gbdt",
        model_version: str = "1.0.0-mock",
        alert_threshold: float = 0.50,
    ):
        # Isotonic calibration breakpoints typical for GBDT margin outputs
        calibrator = IsotonicCalibrator([
            (0.0, 0.02),
            (0.3, 0.15),
            (0.5, 0.50),
            (0.7, 0.82),
            (1.0, 0.99),
        ])
        super().__init__(
            detector_id=detector_id,
            detector_family=DetectorFamily.DET1S_SUPERVISED,
            threat_class=ThreatClass.T_A_DDOS,
            calibrator=calibrator,
            model_version=model_version,
            shared_evidence_domain="volumetric_syn",
            alert_threshold=alert_threshold,
        )

    def predict(self, features: FeatureVector) -> float:
        """Simulates tree ensemble evaluation over packet rate, SYN ratio, and entropy."""
        score = 0.0

        # High packet rate factor
        if features.packets_per_sec > 10000:
            score += 0.45
        elif features.packets_per_sec > 2000:
            score += 0.25

        # Asymmetric SYN to SYN-ACK ratio (SYN flood)
        if features.syn_to_synack_ratio > 10.0:
            score += 0.40
        elif features.syn_to_synack_ratio > 3.0:
            score += 0.20

        # Low entropy from spoofed/concentrated source distributions
        if 0.0 < features.source_ip_entropy < 1.5:
            score += 0.25
        elif features.source_ip_entropy >= 1.5:
            # Reflection flood with high entropy
            if features.packets_per_sec > 5000:
                score += 0.20

        return min(1.0, score)

    def extract_evidence(self, features: FeatureVector, raw_score: float) -> Dict[str, Any]:
        return {
            "packets_per_sec": features.packets_per_sec,
            "syn_count": features.syn_count,
            "syn_ack_count": features.syn_ack_count,
            "syn_to_synack_ratio": round(features.syn_to_synack_ratio, 2),
            "source_ip_entropy": round(features.source_ip_entropy, 2),
            "threat_signature": "SYN_FLOOD_OR_VOLUMETRIC_SPIKE" if raw_score >= 0.5 else "BENIGN_LOAD",
        }
