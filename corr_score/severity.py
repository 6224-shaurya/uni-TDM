"""SCORE severity engine computing f(class_weight, impact_magnitude, asset_criticality) per SAD v2.0 §9.3."""

import math
from typing import Dict, Any, Tuple
from schemas.threats import ThreatClass, SeverityLevel
from schemas.features import FeatureVector
from schemas.alert import RawImpactInputs, AssetProfile
from config.settings import EngineSettings, AssetRegistry, default_settings, default_asset_registry


class ScoreEngine:
    """Evaluates composite threat severity and produces auditable scoring records.
    
    Formula:
        Composite Score S = p_fused * (0.4 * w_class + 0.3 * m_impact + 0.3 * min(1.0, c_asset / 2.0))
        Severity mapped via strict calibrated cutoffs [CRITICAL, HIGH, MEDIUM, LOW, INFO]
    """

    def __init__(
        self,
        settings: EngineSettings = default_settings,
        asset_registry: AssetRegistry = default_asset_registry,
    ):
        self.settings = settings
        self.asset_registry = asset_registry

    def calculate_impact_magnitude(self, threat_class: ThreatClass, features: FeatureVector) -> Tuple[float, Dict[str, Any]]:
        """Calculates normalized impact magnitude m_impact in [0.05, 1.0] and raw metric drivers."""
        m_impact = 0.1
        raw_drivers: Dict[str, Any] = {}

        if threat_class == ThreatClass.T_A_DDOS:
            # Driven by packet throughput and SYN saturation
            pps_term = min(1.0, features.packets_per_sec / 50000.0)
            syn_term = min(1.0, features.syn_to_synack_ratio / 50.0)
            m_impact = 0.6 * pps_term + 0.4 * syn_term
            raw_drivers = {
                "packets_per_sec": features.packets_per_sec,
                "syn_to_synack_ratio": features.syn_to_synack_ratio,
                "syn_count": features.syn_count,
            }

        elif threat_class == ThreatClass.T_F_EXFILTRATION:
            # Driven by outbound byte volume (log10 scale) and transfer asymmetry
            mb_out = features.outbound_bytes / (1024 * 1024)
            # 1 MB -> 0.2, 10 MB -> 0.4, 100 MB -> 0.7, 1 GB+ -> 1.0
            vol_term = min(1.0, max(0.1, math.log10(max(1.0, mb_out) + 1.0) / 3.0))
            ratio_term = min(1.0, features.out_to_in_byte_ratio / 50.0)
            m_impact = 0.7 * vol_term + 0.3 * ratio_term
            raw_drivers = {
                "outbound_bytes": features.outbound_bytes,
                "outbound_mb": round(mb_out, 2),
                "out_to_in_byte_ratio": features.out_to_in_byte_ratio,
            }

        elif threat_class == ThreatClass.T_E_RECON_SCAN:
            # Driven by fanout breadth across ports and target hosts
            port_term = min(1.0, features.hll_distinct_dst_ports / 500.0)
            host_term = min(1.0, features.hll_distinct_dst_hosts / 100.0)
            m_impact = 0.6 * port_term + 0.4 * host_term
            raw_drivers = {
                "distinct_ports": features.hll_distinct_dst_ports,
                "distinct_hosts": features.hll_distinct_dst_hosts,
                "fanout_pps": features.fanout_rate_pps,
            }

        elif threat_class == ThreatClass.T_B_BEACONING:
            # Driven by periodicity power and duration
            m_impact = 0.7 * features.lomb_scargle_power + 0.3 * max(0.0, features.autocorrelation_peak)
            raw_drivers = {
                "lomb_scargle_power": features.lomb_scargle_power,
                "autocorrelation_peak": features.autocorrelation_peak,
                "iat_jitter_mad_ms": features.iat_jitter_mad_ms,
            }

        elif threat_class == ThreatClass.T_C_DGA:
            # Driven by domain entropy and query volume / NXDOMAIN
            entropy_term = min(1.0, features.qname_entropy / 4.5)
            nx_term = min(1.0, features.nxdomain_rate)
            m_impact = 0.6 * entropy_term + 0.4 * nx_term
            raw_drivers = {
                "qname": features.qname,
                "qname_entropy": features.qname_entropy,
                "nxdomain_rate": features.nxdomain_rate,
            }

        elif threat_class == ThreatClass.T_D_ENCRYPTED_MALWARE:
            # Driven by fingerprint rarity
            rarity = max(features.ja3_rarity_score, features.ja4_rarity_score)
            m_impact = max(0.2, rarity)
            raw_drivers = {
                "ja3_rarity": features.ja3_rarity_score,
                "ja4_rarity": features.ja4_rarity_score,
                "ja3_hash": features.ja3_hash,
            }

        m_impact = max(0.05, min(1.0, m_impact))
        return round(m_impact, 4), raw_drivers

    def evaluate_severity(
        self,
        threat_class: ThreatClass,
        fused_confidence: float,
        subject_key: str,
        features: FeatureVector,
    ) -> Tuple[SeverityLevel, RawImpactInputs]:
        """Calculates final severity and creates detailed audit record."""
        # 1. Base threat weight
        w_class = self.settings.threat_base_weights.get(threat_class, 0.70)

        # 2. Asset profile & criticality
        asset_profile: AssetProfile = self.asset_registry.get_profile(subject_key)
        c_asset = asset_profile.criticality

        # 3. Observed impact magnitude
        m_impact, raw_metrics = self.calculate_impact_magnitude(threat_class, features)

        # 4. Composite continuous score S in [0.0, 1.0]
        # Inherent base impact scaled by asset criticality:
        # Base impact combines class lethality (50%) and observed volumetric impact (50%)
        # Multiplied by asset factor (normalized around baseline 1.2)
        base_threat_impact = 0.50 * w_class + 0.50 * m_impact
        asset_scaling = c_asset / 1.5
        composite_impact = min(1.0, base_threat_impact * asset_scaling)
        
        # Final composite score conditioned on detection confidence
        composite_score = fused_confidence * composite_impact
        composite_score = max(0.0, min(1.0, composite_score))

        # 5. Map to discrete severity level
        cutoffs = self.settings.severity_cutoffs
        if composite_score >= cutoffs[SeverityLevel.CRITICAL]:
            severity = SeverityLevel.CRITICAL
            bracket = f"composite_score >= {cutoffs[SeverityLevel.CRITICAL]}"
        elif composite_score >= cutoffs[SeverityLevel.HIGH]:
            severity = SeverityLevel.HIGH
            bracket = f"composite_score >= {cutoffs[SeverityLevel.HIGH]}"
        elif composite_score >= cutoffs[SeverityLevel.MEDIUM]:
            severity = SeverityLevel.MEDIUM
            bracket = f"composite_score >= {cutoffs[SeverityLevel.MEDIUM]}"
        elif composite_score >= cutoffs[SeverityLevel.LOW]:
            severity = SeverityLevel.LOW
            bracket = f"composite_score >= {cutoffs[SeverityLevel.LOW]}"
        else:
            severity = SeverityLevel.INFO
            bracket = "composite_score < LOW_THRESHOLD"

        raw_impact_inputs = RawImpactInputs(
            class_base_weight=w_class,
            observed_impact_magnitude=m_impact,
            asset_criticality=c_asset,
            asset_tier_label=asset_profile.tier_name,
            raw_metrics=raw_metrics,
            confidence_score=round(fused_confidence, 4),
            composite_score=round(composite_score, 4),
            severity_threshold_applied=bracket,
        )

        return severity, raw_impact_inputs


# Global default score engine instance
default_score_engine = ScoreEngine()
