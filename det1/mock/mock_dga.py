"""Mock T-c (DGA / DNS Tunnelling) detector simulating Char-CNN & entropy scoring."""

from typing import Dict, Any
from schemas.features import FeatureVector
from schemas.threats import ThreatClass, DetectorFamily
from det1.base import BaseDetector, PlattCalibrator


class MockDGADetector(BaseDetector):
    """Simulates Character-CNN / n-gram classifier over DNS queries."""

    def __init__(
        self,
        detector_id: str = "mock_det1s_dga_charcnn",
        model_version: str = "1.0.0-mock",
        alert_threshold: float = 0.50,
    ):
        # Logistic sigmoid calibration
        calibrator = PlattCalibrator(a=-5.0, b=2.5)
        super().__init__(
            detector_id=detector_id,
            detector_family=DetectorFamily.DET1S_SUPERVISED,
            threat_class=ThreatClass.T_C_DGA,
            calibrator=calibrator,
            model_version=model_version,
            shared_evidence_domain="dns_entropy",
            alert_threshold=alert_threshold,
        )

    def predict(self, features: FeatureVector) -> float:
        """Infers likelihood of algorithmic domain generation or DNS tunneling."""
        score = 0.0

        # Shannon entropy of qname characters
        if features.qname_entropy > 3.8:
            score += 0.45
        elif features.qname_entropy > 3.2:
            score += 0.25

        # Long domain query string (common in data tunneling or complex DGAs)
        if features.qname_length > 30:
            score += 0.35
        elif features.qname_length > 18:
            score += 0.15

        # NXDOMAIN failure surge
        if features.nxdomain_rate > 0.50:
            score += 0.30
        elif features.nxdomain_rate > 0.20:
            score += 0.15

        return min(1.0, score)

    def extract_evidence(self, features: FeatureVector, raw_score: float) -> Dict[str, Any]:
        return {
            "qname": features.qname or "unknown",
            "qname_entropy": round(features.qname_entropy, 3),
            "qname_length": features.qname_length,
            "nxdomain_rate": round(features.nxdomain_rate, 2),
            "classification_hint": "DGA_OR_DNS_TUNNEL" if raw_score >= 0.5 else "BENIGN_FQDN",
        }
