"""Feature vector and window data representations for the SIH26145 pipeline."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from schemas.threats import SubjectType


class FeatureVector(BaseModel):
    """Unified feature representation across all six detector families (T-a to T-f) and DET0."""

    # T-a (DDoS / Volumetric flood) features
    packets_per_sec: float = Field(default=0.0, ge=0.0, description="Observed packet rate")
    bytes_per_sec: float = Field(default=0.0, ge=0.0, description="Observed byte rate")
    syn_count: int = Field(default=0, ge=0, description="SYN packet count in window")
    syn_ack_count: int = Field(default=0, ge=0, description="SYN-ACK packet count in window")
    rst_count: int = Field(default=0, ge=0, description="RST packet count in window")
    syn_to_synack_ratio: float = Field(default=1.0, ge=0.0, description="SYN / SYN-ACK ratio")
    source_ip_entropy: float = Field(default=0.0, ge=0.0, description="Miller-Madow bias-corrected source IP entropy")

    # T-b (C2 Beaconing / Periodic C2) features
    iat_mean_ms: float = Field(default=0.0, ge=0.0, description="Mean inter-arrival time in ms")
    iat_jitter_mad_ms: float = Field(default=0.0, ge=0.0, description="Median absolute deviation of IAT jitter")
    lomb_scargle_power: float = Field(default=0.0, ge=0.0, le=1.0, description="Peak Lomb-Scargle periodogram spectral power")
    autocorrelation_peak: float = Field(default=0.0, ge=-1.0, le=1.0, description="Maximum lag-1/lag-k autocorrelation peak")
    flow_duration_sec: float = Field(default=0.0, ge=0.0, description="Active flow or session duration in seconds")

    # T-c (DGA / DNS Tunnelling) features
    qname: Optional[str] = Field(default=None, description="DNS query domain name")
    qname_entropy: float = Field(default=0.0, ge=0.0, description="Shannon entropy of qname characters")
    qname_length: int = Field(default=0, ge=0, description="Length of qname in characters")
    subdomain_count: int = Field(default=0, ge=0, description="Count of subdomain labels")
    nxdomain_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of NXDOMAIN responses")
    dns_query_type: Optional[str] = Field(default=None, description="DNS record type (A, TXT, etc.)")

    # T-d (Encrypted Malware / TLS-QUIC) features
    ja3_hash: Optional[str] = Field(default=None, description="JA3 TLS client fingerprint MD5")
    ja4_hash: Optional[str] = Field(default=None, description="JA4 TLS client fingerprint")
    ja3_rarity_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Population rarity score (1.0 = never seen before)")
    ja4_rarity_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Population rarity score for JA4")
    prefix_packet_sizes: List[int] = Field(default_factory=list, description="First N=24 packet sizes (direction-signed)")
    prefix_iat_deltas: List[float] = Field(default_factory=list, description="First N=24 inter-packet delta times (ms)")

    # T-e (Recon / Port-Host Scan) features
    hll_distinct_dst_ports: int = Field(default=0, ge=0, description="HLL estimate of unique destination ports targeted")
    hll_distinct_dst_hosts: int = Field(default=0, ge=0, description="HLL estimate of unique destination IPs targeted")
    fanout_rate_pps: float = Field(default=0.0, ge=0.0, description="New connection attempts per second")
    failed_connection_ratio: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of RST or unacknowledged attempts")

    # T-f (Exfiltration / Asymmetric Outbound Volume) features
    outbound_bytes: int = Field(default=0, ge=0, description="Bytes transferred outbound in window")
    inbound_bytes: int = Field(default=0, ge=0, description="Bytes transferred inbound in window")
    out_to_in_byte_ratio: float = Field(default=1.0, ge=0.0, description="Asymmetry ratio: outbound / inbound bytes")
    volume_deviation_from_baseline: float = Field(default=0.0, description="Z-score or deviation from PROFILE store baseline")

    # Generic or raw feature extensions
    extra_features: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary supplemental feature telemetry")


class WindowData(BaseModel):
    """Represents a closed time window of aggregated traffic for an entity/subject."""
    window_id: str = Field(description="Unique window identifier (e.g., win_src_192.168.1.100_1717200000)")
    window_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Start of window (UTC)")
    window_end: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="End of window (UTC)")
    subject_type: SubjectType = Field(default=SubjectType.SRC_IP, description="Entity subject type")
    subject_key: str = Field(description="Entity subject identifier (e.g., IPv4, IPv6, CIDR, or domain)")
    capture_loss_pct: float = Field(default=0.0, ge=0.0, le=100.0, description="Reported capture loss percentage during window")
    features: FeatureVector = Field(default_factory=FeatureVector, description="Computed feature vector for this window")
    raw_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context or log provenance")
