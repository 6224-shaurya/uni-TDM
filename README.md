# uni-TDM
AI/ML based pipeline which operates as a strictly passive, read-only system and analyzes network traffic flowing through one-way data diodes without ever sending packets back or decrypting content. By using metadata from tools like Zeek or Suricata, no payload decryption, no return path. Streaming detection, calibrated confidence & severity.

## SIH26145 — Cyber Threat Detection Backend (Phase 7 & Phase 8)
### AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

This backend implements **Phase 7** (Detection Tier Assembly) and **Phase 8** (Correlation, Fusion, and Severity Scoring) per the SIH26145 System Architecture Document (SAD v2.0).

---

## Key Architectural Guarantees

1. **Plug-and-Play Model Contract (`det1/base.py`)**:
   - `BaseDetector` exposes identical `.predict(features)` and `.calibrate(raw_score)` methods.
   - Six high-fidelity mock detectors simulate `T-a` through `T-f` models while training continues.
   - When real models (ONNX, joblib, or River) are ready, **only the detector subclass implementation is replaced**. Zero downstream correlation, fusion, or scoring code needs to change.

2. **DET0 Fast-Path Annotator (`det0/annotator.py`)**:
   - Evaluates in parallel with DET1.
   - Emits priority tags (`P0:BurstCritical`, `P1:SuspiciousHeuristic`, `P2:Elevated`, `P3:Normal`).
   - Acts strictly as an annotator—**drops nothing**, preserving 100% flow observability.

3. **Phase 8 Correlation & Fusion (`corr_score/`)**:
   - **SHA-256 Idempotency Key**: `SHA-256(subject_type || subject_key || threat_class || window_start)`.
   - **Noisy-OR with Shared-Evidence Discount**: Groups verdicts by evidence domains (e.g. `volumetric_syn`, `dns_entropy`) and discounts redundant evidence ($\gamma = 0.50$) to prevent artificial probability inflation.
   - **SCORE Severity Engine**: Computes $S = f(w_{\text{class}}, m_{\text{impact}}, c_{\text{asset}})$, maps to discrete levels (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and attaches `raw_impact_inputs` for complete auditability.

4. **FastAPI Serving & Streaming Interface (`api/`)**:
   - REST endpoints for window ingestion, alert querying, detector manifests, and health status.
   - WebSocket streaming (`/ws/alerts`) ready for the Phase 10 dashboard.

---

## Directory Structure

```
├── schemas/                # Pydantic data models & contracts
│   ├── threats.py          # ThreatClass (T-a to T-f), SeverityLevel, PriorityTag
│   ├── features.py         # FeatureVector & WindowData
│   ├── verdict.py          # DetectionVerdict common envelope (§9.1)
│   └── alert.py            # AlertV1 schema & RawImpactInputs (§10.2)
├── det0/                   # Phase 7: Fast-Path Rule Annotator
│   └── annotator.py        # Non-blocking fast-path annotator
├── det1/                   # Phase 7: Deep Detection Tier
│   ├── base.py             # BaseDetector contract & Calibrators (Platt, Isotonic, ECDF)
│   ├── mock/               # Mock detectors for T-a, T-b, T-c, T-d, T-e, T-f
│   ├── registry.py         # DetectorRegistry for plug-and-play swapping
│   └── engine.py           # Parallel fan-out orchestrator
├── corr_score/             # Phase 8: Correlation, Fusion & Severity
│   ├── idempotency.py      # SHA-256 deterministic key generator
│   ├── fusion.py           # Noisy-OR with shared-evidence discount
│   ├── severity.py         # SCORE severity engine & raw impact auditing
│   └── pipeline.py         # End-to-end correlation & scoring pipeline
├── store/                  # In-memory store with SHA-256 ledger chaining
│   └── memory_store.py
├── api/                    # FastAPI serving layer & WebSocket broadcast
│   ├── app.py
│   └── routes.py
├── config/                 # Threat weights, asset registry, thresholds
│   └── settings.py
├── tests/                  # Automated pytest test suite (19 test cases)
└── demo_pipeline.py        # End-to-end multi-threat scenario demo script
```

---

## Quickstart

### 1. Install Dependencies
```bash
pip install fastapi uvicorn pytest pydantic httpx
```

### 2. Run the Automated Test Suite
```bash
python -m pytest tests/ -v
```

### 3. Run the End-to-End Multi-Attack Demo
```bash
python demo_pipeline.py
```

### 4. Start the FastAPI Detection Server
```bash
python -m uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger UI available at: `http://localhost:8000/docs`.

---

## How to Plug in Real Models When Ready

When your trained models arrive from Kaggle/Colab, simply inherit from `BaseDetector`:

```python
from det1.base import BaseDetector, PlattCalibrator
from det1.registry import default_registry
from schemas.threats import ThreatClass, DetectorFamily
from schemas.features import FeatureVector

class RealONNXDDoSDetector(BaseDetector):
    def __init__(self, onnx_model_path: str):
        # 1. Provide fitted calibrator from training validation
        calibrator = PlattCalibrator(a=-8.2, b=4.1)
        super().__init__(
            detector_id="onnx_det1s_ddos",
            detector_family=DetectorFamily.DET1S_SUPERVISED,
            threat_class=ThreatClass.T_A_DDOS,
            calibrator=calibrator,
            model_version="1.0.0-prod",
            shared_evidence_domain="volumetric_syn",
        )
        # Load your ONNX session:
        # import onnxruntime as ort
        # self.session = ort.InferenceSession(onnx_model_path)

    def predict(self, features: FeatureVector) -> float:
        # Run inference against real model artifact
        return float(raw_prediction)

    def extract_evidence(self, features: FeatureVector, raw_score: float):
        return {"feature_importance": ...}

# 2. Swap into registry at startup or runtime:
default_registry.swap(ThreatClass.T_A_DDOS, RealONNXDDoSDetector("models/ddos.onnx"))
```
Zero modifications are needed anywhere else in the application.
