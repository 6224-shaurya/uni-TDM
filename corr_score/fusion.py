"""Noisy-OR fusion engine with shared-evidence discounting per SAD v2.0 §9.2."""

import math
from typing import List, Dict, Tuple, Any
from schemas.verdict import DetectionVerdict


class NoisyORFusionEngine:
    """Combines multi-detector verdicts using Noisy-OR with evidence domain discounting.
    
    Standard Noisy-OR assumes conditional independence between detectors:
        P(threat) = 1 - PROD(1 - p_i)
        
    When DET0 and DET1 share underlying features (e.g., both inspecting SYN flood counters),
    independent combination over-inflates confidence. This engine partitions verdicts into
    evidence domains and applies an evidence discount gamma to redundant signals within
    the same domain before fusing across independent domains.
    """

    def __init__(self, default_discount: float = 0.50):
        self.default_discount = default_discount

    def fuse(
        self,
        verdicts: List[DetectionVerdict],
        discount: float = None,
    ) -> Tuple[float, Dict[str, Any]]:
        """Fuses multiple verdicts into a single posterior probability [0.0, 1.0].
        
        Returns:
            fused_confidence: float in [0.0, 1.0]
            fusion_audit: Dict detailing mathematical breakdown and domain adjustments
        """
        gamma = self.default_discount if discount is None else discount

        if not verdicts:
            return 0.0, {"status": "NO_VERDICTS", "fused_confidence": 0.0}

        if len(verdicts) == 1:
            conf = verdicts[0].calibrated_confidence
            return conf, {
                "status": "SINGLE_VERDICT",
                "fused_confidence": round(conf, 4),
                "domains": {verdicts[0].shared_evidence_domain: [conf]},
                "discount_applied": False,
            }

        # 1. Group confidences by shared evidence domain
        domain_groups: Dict[str, List[Tuple[str, float]]] = {}
        for v in verdicts:
            dom = v.shared_evidence_domain or "general"
            if dom not in domain_groups:
                domain_groups[dom] = []
            domain_groups[dom].append((v.detector_id, v.calibrated_confidence))

        # 2. Within each domain, apply shared-evidence discount to redundant signals
        domain_fused: Dict[str, float] = {}
        audit_details: Dict[str, Any] = {}

        prod_across_domains = 1.0

        for dom, entries in domain_groups.items():
            # Sort descending by confidence: highest signal is treated as primary
            sorted_entries = sorted(entries, key=lambda x: x[1], reverse=True)
            
            p_primary = sorted_entries[0][1]
            prod_within_domain = 1.0 - p_primary

            discounted_secondary = []
            for idx, (det_id, p_sec) in enumerate(sorted_entries[1:], start=1):
                # Discount redundant evidence: p' = p * (gamma ^ idx)
                p_eff = p_sec * (gamma ** idx)
                discounted_secondary.append({
                    "detector_id": det_id,
                    "original_confidence": p_sec,
                    "effective_discounted_confidence": round(p_eff, 4),
                })
                prod_within_domain *= (1.0 - p_eff)

            p_dom = 1.0 - prod_within_domain
            domain_fused[dom] = round(p_dom, 4)
            prod_across_domains *= (1.0 - p_dom)

            audit_details[dom] = {
                "primary_detector": sorted_entries[0][0],
                "primary_confidence": p_primary,
                "secondary_signals": discounted_secondary,
                "domain_fused_confidence": round(p_dom, 4),
            }

        # 3. Fuse across independent domains
        final_fused = 1.0 - prod_across_domains
        # Numerical clamp
        final_fused = max(0.0, min(1.0, final_fused))

        fusion_audit = {
            "fusion_model": "noisy_or_with_shared_evidence_discount",
            "discount_factor_gamma": gamma,
            "domain_breakdown": audit_details,
            "independent_noisy_or_estimate": round(self._standard_noisy_or([v.calibrated_confidence for v in verdicts]), 4),
            "discounted_fused_confidence": round(final_fused, 4),
        }

        return round(final_fused, 4), fusion_audit

    @staticmethod
    def _standard_noisy_or(probs: List[float]) -> float:
        """Helper computing unadjusted independent Noisy-OR for comparison."""
        prod = 1.0
        for p in probs:
            prod *= (1.0 - max(0.0, min(1.0, p)))
        return 1.0 - prod


# Global default fusion engine
default_fusion_engine = NoisyORFusionEngine()
