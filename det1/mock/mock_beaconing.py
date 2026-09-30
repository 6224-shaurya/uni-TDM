"""Mock T-b (C2 Beaconing) detector simulating Lomb-Scargle & jitter MAD anomaly scoring."""

from typing import Dict, Any
from schemas.features import FeatureVector
from schemas.threats import ThreatClass, DetectorFamily
from det1.base import BaseDetector, PlattCalibrator


class MockBeaconingDetector(BaseDetector):
    """Simulates Lomb-Scargle periodogram and autocorrelation peak anomaly scoring."""

    def __init__(
        self,
        detector_id: str = "mock_det1a_beaconing_ls",
        model_version: str = "1.0.0-mock",
        alert_threshold: float = 0.50,
    ):
        # Logistic sigmoid calibration over spectral periodicity score
        calibrator = PlattCalibrator(a=-4.0, b=2.0)
        super().__init__(
            detector_id=detector_id,
            detector_family=DetectorFamily.DET1A_ANOMALY,
            threat_class=ThreatClass.T_B_BEACONING,
            calibrator=calibrator,
            model_version=model_version,
            shared_evidence_domain="timing_periodic",
            alert_threshold=alert_threshold,
        )

    def predict(self, features: FeatureVector) -> float:
        """Evaluates periodicity consistency and low-jitter heartbeat behavior."""
        score = 0.0

        # Lomb-Scargle spectral peak
        if features.lomb_scargle_power > 0.70:
            score += 0.50
        elif features.lomb_scargle_power > 0.40:
            score += 0.25

        # Autocorrelation lag peak
        if features.autocorrelation_peak > 0.75:
            score += 0.35
        elif features.autocorrelation_peak > 0.40:
            score += 0.15

        # Strict low jitter MAD (< 50ms) characteristic of automated C2 beacons
        if 0.0 < features.iat_jitter_mad_ms < 50.0 and features.lomb_scargle_power > 0.3:
            score += 0.25
        elif features.iat_jitter_mad_ms > 500.0:
            # Human or benign jitter discount
            score -= 0.20

        return max(0.0, min(1.0, score))

    def extract_evidence(self, features: FeatureVector, raw_score: float) -> Dict[str, Any]:
        return {
            "lomb_scargle_power": round(features.lomb_scargle_power, 3),
            "autocorrelation_peak": round(features.autocorrelation_peak, 3),
            "iat_jitter_mad_ms": round(features.iat_jitter_mad_ms, 2),
            "iat_mean_ms": round(features.iat_mean_ms, 2),
            "periodicity_status": "RIGID_PERIODIC_HEARTBEAT" if raw_score >= 0.5 else "IRREGULAR_TRAFFIC",
        }
