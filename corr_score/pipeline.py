"""Correlation, fusion, and severity scoring pipeline per SAD v2.0 §9."""

import time
from datetime import datetime, timezone
from typing import List, Dict, Optional
from schemas.features import WindowData
from schemas.verdict import DetectionVerdict
from schemas.alert import AlertV1
from schemas.threats import ThreatClass, PriorityTag
from corr_score.idempotency import generate_idempotency_key
from corr_score.fusion import NoisyORFusionEngine, default_fusion_engine
from corr_score.severity import ScoreEngine, default_score_engine


class CorrelationPipeline:
    """End-to-end Phase 8 pipeline: Groups verdicts -> Fuses with Noisy-OR -> Scores severity."""

    def __init__(
        self,
        fusion_engine: Optional[NoisyORFusionEngine] = None,
        score_engine: Optional[ScoreEngine] = None,
        alert_confidence_threshold: float = 0.40,
    ):
        self.fusion_engine = fusion_engine or default_fusion_engine
        self.score_engine = score_engine or default_score_engine
        self.alert_confidence_threshold = alert_confidence_threshold

    def process_window(self, window: WindowData, verdicts: List[DetectionVerdict]) -> List[AlertV1]:
        """Correlates verdicts for a single window, fuses evidence, and generates alerts."""
        start_eval_time = time.monotonic()

        # 1. Partition alert-worthy or threat-associated verdicts by ThreatClass
        threat_groups: Dict[ThreatClass, List[DetectionVerdict]] = {}
        highest_det0_tag = PriorityTag.P3_NORMAL

        for v in verdicts:
            # Check DET0 fast-path priority tag
            if v.priority_tag == PriorityTag.P0_BURST_CRITICAL:
                highest_det0_tag = PriorityTag.P0_BURST_CRITICAL
            elif v.priority_tag == PriorityTag.P1_SUSPICIOUS_HEURISTIC and highest_det0_tag != PriorityTag.P0_BURST_CRITICAL:
                highest_det0_tag = PriorityTag.P1_SUSPICIOUS_HEURISTIC

            if v.threat_class:
                if v.threat_class not in threat_groups:
                    threat_groups[v.threat_class] = []
                threat_groups[v.threat_class].append(v)

        alerts: List[AlertV1] = []

        # 2. For each threat class identified across DET0 and DET1, fuse and score
        for threat_class, group_verdicts in threat_groups.items():
            # Check if any verdict in the group flagged as alert-worthy or high confidence
            has_alert_worthy = any(v.is_alert_worthy for v in group_verdicts)
            
            # Check highest priority tag specifically within this threat group (e.g. from DET0)
            group_highest_tag = PriorityTag.P3_NORMAL
            for v in group_verdicts:
                if v.priority_tag == PriorityTag.P0_BURST_CRITICAL:
                    group_highest_tag = PriorityTag.P0_BURST_CRITICAL
                elif v.priority_tag == PriorityTag.P1_SUSPICIOUS_HEURISTIC and group_highest_tag != PriorityTag.P0_BURST_CRITICAL:
                    group_highest_tag = PriorityTag.P1_SUSPICIOUS_HEURISTIC
            
            # Fuse confidences with shared-evidence discount
            fused_conf, fusion_audit = self.fusion_engine.fuse(group_verdicts)

            # Fast-path P0/P1 tags lower the barrier for the flagged threat class
            threshold = (
                0.25 if group_highest_tag in (PriorityTag.P0_BURST_CRITICAL, PriorityTag.P1_SUSPICIOUS_HEURISTIC)
                else self.alert_confidence_threshold
            )

            if not has_alert_worthy and fused_conf < threshold:
                # Sub-threshold signal: no alert generated
                continue

            # 3. Generate deterministic SHA-256 idempotency key
            idempotency_key = generate_idempotency_key(
                subject_type=window.subject_type,
                subject_key=window.subject_key,
                threat_class=threat_class,
                window_start=window.window_start,
            )

            # 4. Compute severity and raw impact audit
            severity, raw_impact = self.score_engine.evaluate_severity(
                threat_class=threat_class,
                fused_confidence=fused_conf,
                subject_key=window.subject_key,
                features=window.features,
            )

            # Determine aggregate priority tag
            peak_tag = highest_det0_tag
            if peak_tag == PriorityTag.P3_NORMAL and any(v.is_alert_worthy for v in group_verdicts):
                peak_tag = PriorityTag.P2_ELEVATED

            latency_ms = (time.monotonic() - start_eval_time) * 1000.0

            alert = AlertV1(
                idempotency_key=idempotency_key,
                threat_class=threat_class,
                severity=severity,
                fused_confidence=fused_conf,
                subject_type=window.subject_type,
                subject_key=window.subject_key,
                window_id=window.window_id,
                window_start=window.window_start,
                window_end=window.window_end,
                priority_tag=peak_tag,
                contributing_verdicts=group_verdicts,
                raw_impact_inputs=raw_impact,
                capture_loss_pct=window.capture_loss_pct,
                observed_latency_ms=round(latency_ms, 2),
                clock_source="monotonic_utc",
                created_at=datetime.now(timezone.utc),
            )
            alerts.append(alert)

        return alerts


# Global default correlation pipeline
default_correlation_pipeline = CorrelationPipeline()
