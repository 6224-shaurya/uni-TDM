"""Threat classifications, severity levels, and operational tags."""

from enum import Enum


class ThreatClass(str, Enum):
    """The six primary threat classes defined in SAD v2.0."""
    T_A_DDOS = "T-a:DDoS"
    T_B_BEACONING = "T-b:Beaconing"
    T_C_DGA = "T-c:DGA/DNS"
    T_D_ENCRYPTED_MALWARE = "T-d:EncryptedMalware"
    T_E_RECON_SCAN = "T-e:Recon/Scan"
    T_F_EXFILTRATION = "T-f:Exfiltration"


class SeverityLevel(str, Enum):
    """Standardized 5-tier severity classification."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PriorityTag(str, Enum):
    """DET0 Fast-Path priority tags (annotated, not gated)."""
    P0_BURST_CRITICAL = "P0:BurstCritical"
    P1_SUSPICIOUS_HEURISTIC = "P1:SuspiciousHeuristic"
    P2_ELEVATED = "P2:Elevated"
    P3_NORMAL = "P3:Normal"


class DetectorFamily(str, Enum):
    """Architecture detector family classification."""
    DET0_FAST_PATH = "DET0:FastPath"
    DET1S_SUPERVISED = "DET1S:Supervised"
    DET1A_ANOMALY = "DET1A:Anomaly"


class SubjectType(str, Enum):
    """Subject entities for grouping and correlation."""
    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    IP_PAIR = "ip_pair"
    DOMAIN = "domain"
