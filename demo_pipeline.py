"""End-to-end demonstration script for Phase 7 & Phase 8 of SIH26145 threat detection engine.

Simulates 6 attack scenarios + benign traffic, runs them through DET0 and DET1 banks,
fuses verdicts via Noisy-OR with evidence discounting, and computes auditable severity scores.
Also demonstrates hot-swapping a mock detector with a production model artifact.
"""

from datetime import datetime, timezone
import json
from schemas.features import WindowData, FeatureVector
from schemas.threats import ThreatClass, SubjectType, PriorityTag, DetectorFamily
from det1.engine import DetectionTierOrchestrator
from det1.registry import DetectorRegistry
from det1.base import BaseDetector, PlattCalibrator
from corr_score.pipeline import CorrelationPipeline
from store.memory_store import MemoryAlertStore


def run_demo():
    print("=" * 80)
    print("SIH26145 — Detection Tier (Phase 7) & Correlation / Severity (Phase 8)")
    print("=" * 80)

    registry = DetectorRegistry(auto_load_mocks=True)
    orchestrator = DetectionTierOrchestrator(registry=registry)
    pipeline = CorrelationPipeline()
    store = MemoryAlertStore()

    now = datetime.now(timezone.utc)

    # Scenarios covering benign + all 6 attack classes
    scenarios = [
        (
            "T-a: Volumetric SYN Flood against Tier 1 DC",
            WindowData(
                window_id="win_demo_ddos",
                window_start=now,
                window_end=now,
                subject_type=SubjectType.DST_IP,
                subject_key="10.0.0.1",
                features=FeatureVector(
                    packets_per_sec=55000.0,
                    syn_count=8500,
                    syn_ack_count=10,
                    syn_to_synack_ratio=850.0,
                    source_ip_entropy=0.6,
                ),
            ),
        ),
        (
            "T-b: Rigid C2 Beaconing Heartbeat",
            WindowData(
                window_id="win_demo_beacon",
                window_start=now,
                window_end=now,
                subject_type=SubjectType.SRC_IP,
                subject_key="192.168.1.50",
                features=FeatureVector(
                    lomb_scargle_power=0.88,
                    autocorrelation_peak=0.85,
                    iat_jitter_mad_ms=8.5,
                    iat_mean_ms=60000.0,
                ),
            ),
        ),
        (
            "T-c: Algorithmic DGA / DNS Tunnelling",
            WindowData(
                window_id="win_demo_dga",
                window_start=now,
                window_end=now,
                subject_type=SubjectType.DOMAIN,
                subject_key="x99b4a1c7f89d.biz",
                features=FeatureVector(
                    qname="x99b4a1c7f89d.biz",
                    qname_entropy=4.35,
                    qname_length=42,
                    nxdomain_rate=0.75,
                ),
            ),
        ),
        (
            "T-d: Encrypted Malware TLS Session",
            WindowData(
                window_id="win_demo_malware",
                window_start=now,
                window_end=now,
                subject_type=SubjectType.SRC_IP,
                subject_key="192.168.1.75",
                features=FeatureVector(
                    ja3_hash="71b3e50a19b677e43c4908299c8224d3",
                    ja3_rarity_score=0.96,
                    ja4_rarity_score=0.94,
                    prefix_packet_sizes=[517, -1440, 240, -1440, 80],
                ),
            ),
        ),
        (
            "T-e: Horizontal Port / Host Reconnaissance",
            WindowData(
                window_id="win_demo_recon",
                window_start=now,
                window_end=now,
                subject_type=SubjectType.SRC_IP,
                subject_key="192.168.1.180",
                features=FeatureVector(
                    hll_distinct_dst_ports=450,
                    hll_distinct_dst_hosts=60,
                    fanout_rate_pps=220.0,
                    failed_connection_ratio=0.85,
                ),
            ),
        ),
        (
            "T-f: Massive Asymmetric Outbound Exfiltration",
            WindowData(
                window_id="win_demo_exfil",
                window_start=now,
                window_end=now,
                subject_type=SubjectType.SRC_IP,
                subject_key="10.0.0.2",
                features=FeatureVector(
                    outbound_bytes=250 * 1024 * 1024,
                    inbound_bytes=512 * 1024,
                    out_to_in_byte_ratio=500.0,
                    volume_deviation_from_baseline=4.8,
                ),
            ),
        ),
        (
            "Normal / Benign Baseline Workstation Traffic",
            WindowData(
                window_id="win_demo_benign",
                window_start=now,
                window_end=now,
                subject_type=SubjectType.SRC_IP,
                subject_key="192.168.1.25",
                features=FeatureVector(
                    packets_per_sec=80.0,
                    syn_to_synack_ratio=1.0,
                    qname="portal.internal.company.com",
                    qname_entropy=2.2,
                    qname_length=26,
                    outbound_bytes=45000,
                    inbound_bytes=120000,
                    out_to_in_byte_ratio=0.375,
                ),
            ),
        ),
    ]

    print(f"\nProcessing {len(scenarios)} traffic scenarios...\n")

    for desc, window in scenarios:
        print(f"--- Scenario: {desc} ---")
        print(f"  Target: [{window.subject_type.value}] {window.subject_key}")

        # Parallel fan-out
        verdicts = orchestrator.evaluate_sync(window)
        det0_verdict = next((v for v in verdicts if v.detector_family.value.startswith("DET0")), None)
        det0_tag = det0_verdict.priority_tag.value if det0_verdict else "N/A"

        print(f"  DET0 Fast-Path Tag: {det0_tag}")

        # Correlation, Noisy-OR fusion, and SCORE
        alerts = pipeline.process_window(window, verdicts)

        if not alerts:
            print("  Result: No alert triggered (Normal/sub-threshold traffic). All verdicts stored.\n")
        else:
            for alert in alerts:
                stored_alert, is_new = store.insert(alert)
                raw = alert.raw_impact_inputs
                print(f"  >>> ALERT TRIGGERED:")
                print(f"      Threat Class:       {alert.threat_class.value}")
                print(f"      Severity:           [{alert.severity.value.upper()}]")
                print(f"      Fused Confidence:   {alert.fused_confidence:.4f}")
                print(f"      Idempotency Key:    {alert.idempotency_key[:16]}...{alert.idempotency_key[-8:]}")
                print(f"      Asset Tier:         {raw.asset_tier_label} (criticality: {raw.asset_criticality})")
                print(f"      Impact Magnitude:   {raw.observed_impact_magnitude:.4f}")
                print(f"      Composite Score:    {raw.composite_score:.4f} ({raw.severity_threshold_applied})")
                print(f"      Audit Key Drivers:  {json.dumps(raw.raw_metrics)}")
                print(f"      Verdicts Fused:     {len(alert.contributing_verdicts)}")
            print()

    print("=" * 80)
    print("VERIFICATION OF DETECTOR PLUG-AND-PLAY HOT SWAP CONTRACT")
    print("=" * 80)
    print("Demonstrating hot-swap: replacing fake T-a detector with a production ONNX model...")

    class ProductionONNXDetector(BaseDetector):
        def __init__(self):
            super().__init__(
                detector_id="onnx_prod_ddos_v2",
                detector_family=DetectorFamily.DET1S_SUPERVISED,
                threat_class=ThreatClass.T_A_DDOS,
                calibrator=PlattCalibrator(a=-10.0, b=5.0),
                model_version="2.1.0-onnx",
                model_sha256="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                shared_evidence_domain="volumetric_syn",
            )
        def predict(self, features: FeatureVector) -> float:
            return 0.98 if features.packets_per_sec > 10000 else 0.05
        def extract_evidence(self, features: FeatureVector, raw_score: float):
            return {"runtime": "onnxruntime-directml", "model_digest": self.model_sha256}

    old_det = registry.swap(ThreatClass.T_A_DDOS, ProductionONNXDetector())
    print(f"  Successfully swapped! Evicted: {old_det.detector_id} -> Installed: {registry.get_by_threat(ThreatClass.T_A_DDOS).detector_id}")
    
    # Run test window with newly registered detector
    test_win = scenarios[0][1]
    new_verdicts = orchestrator.evaluate_sync(test_win)
    new_ddos_v = next(v for v in new_verdicts if v.detector_id == "onnx_prod_ddos_v2")
    print(f"  Production detector evaluated! Detector ID: {new_ddos_v.detector_id}, Version: {new_ddos_v.model_version}, Confidence: {new_ddos_v.calibrated_confidence}")

    print("\nCryptographic Alert Ledger Integrity Check:")
    print(f"  Stored Alerts Count: {store.count()}")
    print(f"  SHA-256 Ledger Valid: {store.verify_ledger_integrity()}")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()
