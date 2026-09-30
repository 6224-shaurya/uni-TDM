"""Alert schema (alert.v1) and audit models as tabulated in SAD v2.0 §10.2."""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from schemas.threats import ThreatClass, SeverityLevel, PriorityTag, SubjectType
from schemas.verdict import DetectionVerdict


class RawImpactInputs(BaseModel):
    """Raw calculation inputs preserved alongside severity for full auditability (§9.3, §10.2)."""
    class_base_weight: float = Field(description="Inherent threat impact weight w_class")
    observed_impact_magnitude: float = Field(description="Volumetric/behavioral impact magnitude m_impact [0.0, 1.0]")
    asset_criticality: float = Field(description="Criticality coefficient of target asset c_asset")
    asset_tier_label: str = Field(description="Human-readable asset tier name")
    
    raw_metrics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Underlying raw metrics (e.g., bytes_out, pps, distinct_ports, entropy) driving impact"
    )
    confidence_score: float = Field(description="Noisy-OR fused confidence p_fused")
    composite_score: float = Field(description="Final computed continuous score S before thresholding")
    severity_threshold_applied: str = Field(description="Rule or bracket that matched the final severity")


class AssetProfile(BaseModel):
    """Network asset information used by SCORE engine to weight impact."""
    subject_key: str = Field(description="IP address, CIDR, or domain name")
    criticality: float = Field(default=1.0, ge=0.5, le=3.0, description="Criticality coefficient")
    tier_name: str = Field(default="Standard Host (Tier 3)", description="Human readable tier")
    description: Optional[str] = Field(default=None, description="Asset role (e.g. 'Primary Active Directory DC')")
    tags: List[str] = Field(default_factory=list, description="Asset classification tags")


class AlertV1(BaseModel):
    """Complete alert.v1 contract conforming to SAD v2.0 §10.2."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique alert UUID")
    idempotency_key: str = Field(
        description="SHA-256(subject_type || subject_key || threat_class || window_start) hex string"
    )
    threat_class: ThreatClass = Field(description="Primary classified threat family (T-a through T-f)")
    severity: SeverityLevel = Field(description="Assigned severity (info, low, medium, high, critical)")
    fused_confidence: float = Field(ge=0.0, le=1.0, description="Noisy-OR fused calibrated confidence")
    
    subject_type: SubjectType = Field(description="Subject entity type")
    subject_key: str = Field(description="Subject entity identifier (e.g. attacker IP or victim server)")
    
    window_id: str = Field(description="Window ID of triggering batch")
    window_start: datetime = Field(description="Window start time (UTC)")
    window_end: datetime = Field(description="Window end time (UTC)")
    
    priority_tag: PriorityTag = Field(default=PriorityTag.P3_NORMAL, description="Peak fast-path priority tag")
    contributing_verdicts: List[DetectionVerdict] = Field(
        default_factory=list,
        description="All DET0 and DET1 verdicts fused into this alert"
    )
    
    raw_impact_inputs: RawImpactInputs = Field(
        description="Audit record of exact components used to derive severity"
    )
    
    # SLO self-measurement & operational telemetry fields
    capture_loss_pct: float = Field(default=0.0, description="Reported network capture loss in window")
    observed_latency_ms: float = Field(default=0.0, description="End-to-end detection latency (window_end to alert)")
    clock_source: str = Field(default="ptp_monotonic", description="Clock reference used for latency telemetry")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Alert creation time")
