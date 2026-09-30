"""Mock T-e (Recon / Port-Host Scan) detector simulating HLL cardinality classifier."""

from typing import Dict, Any
from schemas.features import FeatureVector
from schemas.threats import ThreatClass, DetectorFamily
from det1.base import BaseDetector, IsotonicCalibrator


class MockReconDetector(BaseDetector):
    """Simulates classifier over HLL distinct destination port/host counts and fanout rates."""

    def __init__(
        self,
        detector_id: str = "mock_det1s_recon_hll",
        model_version: str = "1.0.0-mock",
        alert_threshold: float = 0.50,
    ):
        calibrator = IsotonicCalibrator([
            (0.0, 0.01),
            (0.2, 0.10),
            (0.4, 0.40),
            (0.6, 0.75),
            (1.0, 0.98),
        ])
        super().__init__(
            detector_id=detector_id,
            detector_family=DetectorFamily.DET1S_SUPERVISED,
            threat_class=ThreatClass.T_E_RECON_SCAN,
            calibrator=calibrator,
            model_version=model_version,
            shared_evidence_domain="scan_fanout",
            alert_threshold=alert_threshold,
        )

    def predict(self, features: FeatureVector) -> float:
        score = 0.0

        # Port scan: high distinct destination ports on few targets
        if features.hll_distinct_dst_ports > 100:
            score += 0.55
        elif features.hll_distinct_dst_ports > 25:
            score += 0.30

        # Host sweep: high distinct destination hosts
        if features.hll_distinct_dst_hosts > 50:
            score += 0.40
        elif features.hll_distinct_dst_hosts > 15:
            score += 0.20

        # Connection failure or RST ratio
        if features.failed_connection_ratio > 0.60:
            score += 0.25

        # Fanout rate pps
        if features.fanout_rate_pps > 100.0:
            score += 0.20

        return min(1.0, score)

    def extract_evidence(self, features: FeatureVector, raw_score: float) -> Dict[str, Any]:
        return {
            "hll_distinct_dst_ports": features.hll_distinct_dst_ports,
            "hll_distinct_dst_hosts": features.hll_distinct_dst_hosts,
            "fanout_rate_pps": round(features.fanout_rate_pps, 2),
            "failed_connection_ratio": round(features.failed_connection_ratio, 2),
            "scan_pattern": "ACTIVE_PORT_OR_HOST_SWEEP" if raw_score >= 0.5 else "NORMAL_FANOUT",
        }
