"""Common detection verdict envelope (§9.1) emitted by DET0 and DET1."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, Any
from pydantic import BaseModel, Field

from schemas.threats import ThreatClass, DetectorFamily, PriorityTag, SubjectType


class DetectionVerdict(BaseModel):
    """Unified verdict envelope emitted by both DET0 fast-path and DET1 deep detector banks."""
    verdict_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique verdict UUID")
    detector_id: str = Field(description="Identifier of emitting detector (e.g. 'mock_det1s_ddos')")
    detector_family: DetectorFamily = Field(description="DET0_FAST_PATH, DET1S_SUPERVISED, or DET1A_ANOMALY")
    threat_class: Optional[ThreatClass] = Field(default=None, description="Identified threat class if flagged")
    
    subject_type: SubjectType = Field(description="Subject entity type (src_ip, dst_ip, etc.)")
    subject_key: str = Field(description="Subject entity value (e.g., '192.168.1.50')")
    
    window_id: str = Field(description="Associated feature window ID")
    window_start: datetime = Field(description="Start timestamp of feature window (UTC)")
    window_end: datetime = Field(description="End timestamp of feature window (UTC)")
    
    raw_score: float = Field(description="Raw uncalibrated score directly from detector model")
    calibrated_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Calibrated confidence [0.0, 1.0]")
    
    priority_tag: PriorityTag = Field(default=PriorityTag.P3_NORMAL, description="Fast-path priority annotation")
    is_alert_worthy: bool = Field(default=False, description="Whether verdict crosses initial screening threshold")
    
    evidence_features: Dict[str, Any] = Field(default_factory=dict, description="Key features or reasons explaining verdict")
    shared_evidence_domain: str = Field(
        default="general",
        description="Evidence domain tag (e.g. 'volumetric', 'dns', 'timing', 'fingerprint', 'scan', 'exfiltration') for fusion discount"
    )
    
    model_version: str = Field(default="1.0.0", description="Version of the model that generated this verdict")
    model_sha256: Optional[str] = Field(default=None, description="Digest of model artifact for provenance verification")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Evaluation timestamp")
