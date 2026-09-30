"""Configuration settings, threat base weights, and asset registry for SIH26145."""

from typing import Dict, Optional
from pydantic import BaseModel, Field
from schemas.threats import ThreatClass, SeverityLevel
from schemas.alert import AssetProfile


class EngineSettings(BaseModel):
    """Configuration parameters for detection, fusion, and scoring."""

    # Threat Class Base Weights w_class (Inherent impact / lethality)
    threat_base_weights: Dict[ThreatClass, float] = Field(
        default={
            ThreatClass.T_A_DDOS: 0.85,
            ThreatClass.T_B_BEACONING: 0.75,
            ThreatClass.T_C_DGA: 0.70,
            ThreatClass.T_D_ENCRYPTED_MALWARE: 0.80,
            ThreatClass.T_E_RECON_SCAN: 0.50,
            ThreatClass.T_F_EXFILTRATION: 0.95,
        }
    )

    # Correlation & Fusion parameters
    shared_evidence_discount: float = Field(
        default=0.50,
        ge=0.0,
        le=1.0,
        description="Discount factor applied to subsequent redundant verdicts sharing evidence domain"
    )
    
    alert_worthy_confidence_threshold: float = Field(
        default=0.45,
        ge=0.0,
        le=1.0,
        description="Minimum calibrated confidence or fast-path tag required to raise an alert"
    )

    # Score-to-Severity thresholds
    severity_cutoffs: Dict[SeverityLevel, float] = Field(
        default={
            SeverityLevel.CRITICAL: 0.80,
            SeverityLevel.HIGH: 0.60,
            SeverityLevel.MEDIUM: 0.40,
            SeverityLevel.LOW: 0.20,
            SeverityLevel.INFO: 0.00,
        }
    )

    # Default asset profile for unknown / unclassified entities
    default_asset_criticality: float = 1.0


class AssetRegistry:
    """In-memory asset inventory providing criticality lookups for SCORE engine."""

    def __init__(self, default_criticality: float = 1.0):
        self.default_criticality = default_criticality
        self._profiles: Dict[str, AssetProfile] = {
            "10.0.0.1": AssetProfile(
                subject_key="10.0.0.1",
                criticality=2.0,
                tier_name="Tier 1 - Primary Active Directory & Identity Server",
                description="Core authentication and directory services",
                tags=["domain_controller", "identity", "p1_asset"],
            ),
            "10.0.0.2": AssetProfile(
                subject_key="10.0.0.2",
                criticality=1.9,
                tier_name="Tier 1 - Relational Database Cluster (PostgreSQL)",
                description="Customer sensitive financial ledger",
                tags=["database", "customer_data", "p1_asset"],
            ),
            "10.0.0.254": AssetProfile(
                subject_key="10.0.0.254",
                criticality=1.8,
                tier_name="Tier 1 - Core Enclave Edge Firewall & Ingress Diode",
                description="Unidirectional network diode gateway",
                tags=["gateway", "firewall", "diode"],
            ),
            "192.168.1.50": AssetProfile(
                subject_key="192.168.1.50",
                criticality=1.4,
                tier_name="Tier 2 - Internal Build & Artifact Pipeline",
                description="CI/CD internal build server",
                tags=["cicd", "devops"],
            ),
            "172.16.10.5": AssetProfile(
                subject_key="172.16.10.5",
                criticality=0.8,
                tier_name="Tier 4 - Guest Network Segment",
                description="Isolated guest and IoT subnet",
                tags=["guest", "untrusted"],
            ),
        }

    def get_profile(self, subject_key: str) -> AssetProfile:
        """Looks up asset profile or returns standard host baseline."""
        if subject_key in self._profiles:
            return self._profiles[subject_key]
        
        # Subnet prefix matchers
        if subject_key.startswith("10.0."):
            return AssetProfile(
                subject_key=subject_key,
                criticality=1.5,
                tier_name="Tier 2 - Enterprise Core Infrastructure Subnet",
                tags=["core_infra"],
            )
        elif subject_key.startswith("172.16."):
            return AssetProfile(
                subject_key=subject_key,
                criticality=0.8,
                tier_name="Tier 4 - DMZ / Guest Range",
                tags=["dmz_guest"],
            )
            
        return AssetProfile(
            subject_key=subject_key,
            criticality=self.default_criticality,
            tier_name="Tier 3 - Standard Workstation / Endpoint",
            tags=["standard_workstation"],
        )

    def register_profile(self, profile: AssetProfile) -> None:
        """Add or update an asset profile."""
        self._profiles[profile.subject_key] = profile


# Global default configuration instance
default_settings = EngineSettings()
default_asset_registry = AssetRegistry()
