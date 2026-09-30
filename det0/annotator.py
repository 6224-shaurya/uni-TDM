"""DET0 Fast-Path Rule Annotator per SAD v2.0 §4.2, §8.1.

DET0 is strictly an annotator, NOT a gate:
- Fans out in parallel with DET1
- Emits fast-path verdict + priority tag
- Drops nothing (verdicts are emitted for all evaluated windows)
"""

from typing import Dict, Any, Tuple, Optional
from schemas.features import WindowData, FeatureVector
from schemas.verdict import DetectionVerdict
from schemas.threats import ThreatClass, DetectorFamily, PriorityTag


class FastPathAnnotator:
    """Non-blocking fast-path annotator providing immediate priority tags and heuristic screening."""

    def __init__(self, detector_id: str = "det0_fast_path_annotator", version: str = "1.0.0"):
        self.detector_id = detector_id
        self.version = version

    def annotate(self, window: WindowData) -> DetectionVerdict:
        """Evaluates traffic window against high-throughput deterministic heuristics.
        
        Always emits a verdict envelope without dropping any traffic.
        """
        f: FeatureVector = window.features
        
        priority_tag = PriorityTag.P3_NORMAL
        suspected_threat: Optional[ThreatClass] = None
        evidence: Dict[str, Any] = {}
        raw_score = 0.0
        calibrated_conf = 0.0
        evidence_domain = "general"

        # Heuristic 1: Extreme Volumetric or SYN flood spike
        if f.packets_per_sec > 50000 or (f.syn_count > 2000 and f.syn_ack_count == 0):
            priority_tag = PriorityTag.P0_BURST_CRITICAL
            suspected_threat = ThreatClass.T_A_DDOS
            raw_score = 0.95
            calibrated_conf = 0.95
            evidence_domain = "volumetric_syn"
            evidence = {
                "rule": "RULE_CRITICAL_SYN_BURST",
                "pps": f.packets_per_sec,
                "syn_count": f.syn_count,
                "syn_ack_count": f.syn_ack_count,
            }
        elif f.packets_per_sec > 10000 or f.syn_to_synack_ratio > 20.0:
            priority_tag = PriorityTag.P1_SUSPICIOUS_HEURISTIC
            suspected_threat = ThreatClass.T_A_DDOS
            raw_score = 0.75
            calibrated_conf = 0.72
            evidence_domain = "volumetric_syn"
            evidence = {
                "rule": "RULE_ELEVATED_SYN_RATIO",
                "syn_to_synack_ratio": f.syn_to_synack_ratio,
                "pps": f.packets_per_sec,
            }

        # Heuristic 2: Mass Exfiltration Volume Spike
        elif f.outbound_bytes > 100 * 1024 * 1024 and f.out_to_in_byte_ratio > 50.0:
            priority_tag = PriorityTag.P0_BURST_CRITICAL
            suspected_threat = ThreatClass.T_F_EXFILTRATION
            raw_score = 0.92
            calibrated_conf = 0.90
            evidence_domain = "asymmetric_transfer"
            evidence = {
                "rule": "RULE_MASS_OUTBOUND_EXFIL",
                "outbound_bytes": f.outbound_bytes,
                "out_to_in_byte_ratio": f.out_to_in_byte_ratio,
            }

        # Heuristic 3: Rapid Fan-out Reconnaissance / Sweep
        elif f.hll_distinct_dst_ports > 500 or f.fanout_rate_pps > 250.0:
            priority_tag = PriorityTag.P1_SUSPICIOUS_HEURISTIC
            suspected_threat = ThreatClass.T_E_RECON_SCAN
            raw_score = 0.80
            calibrated_conf = 0.78
            evidence_domain = "scan_fanout"
            evidence = {
                "rule": "RULE_HIGH_FANOUT_SCAN",
                "distinct_ports": f.hll_distinct_dst_ports,
                "fanout_pps": f.fanout_rate_pps,
            }

        # Heuristic 4: Obvious High-Entropy DGA domain
        elif f.qname_entropy > 4.2 and f.qname_length > 35:
            priority_tag = PriorityTag.P1_SUSPICIOUS_HEURISTIC
            suspected_threat = ThreatClass.T_C_DGA
            raw_score = 0.85
            calibrated_conf = 0.80
            evidence_domain = "dns_entropy"
            evidence = {
                "rule": "RULE_HIGH_ENTROPY_QNAME",
                "qname": f.qname,
                "entropy": f.qname_entropy,
                "length": f.qname_length,
            }

        # Normal / Baseline traffic: Emit P3_NORMAL, drop nothing
        else:
            priority_tag = PriorityTag.P3_NORMAL
            raw_score = 0.05
            calibrated_conf = 0.05
            evidence = {"status": "NO_FAST_PATH_ANOMALY"}

        is_alert_worthy = priority_tag in (PriorityTag.P0_BURST_CRITICAL, PriorityTag.P1_SUSPICIOUS_HEURISTIC)

        return DetectionVerdict(
            detector_id=self.detector_id,
            detector_family=DetectorFamily.DET0_FAST_PATH,
            threat_class=suspected_threat,
            subject_type=window.subject_type,
            subject_key=window.subject_key,
            window_id=window.window_id,
            window_start=window.window_start,
            window_end=window.window_end,
            raw_score=round(raw_score, 4),
            calibrated_confidence=round(calibrated_conf, 4),
            priority_tag=priority_tag,
            is_alert_worthy=is_alert_worthy,
            evidence_features=evidence,
            shared_evidence_domain=evidence_domain,
            model_version=self.version,
            model_sha256="det0-rule-engine-v1",
        )


# Global default DET0 instance
default_annotator = FastPathAnnotator()
