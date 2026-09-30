"""API route handlers for SIH26145 detection backend."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from schemas.features import WindowData
from schemas.verdict import DetectionVerdict
from schemas.alert import AlertV1
from schemas.threats import ThreatClass, SeverityLevel
from det1.engine import default_orchestrator, DetectionTierOrchestrator
from det1.registry import default_registry, DetectorRegistry
from corr_score.pipeline import default_correlation_pipeline, CorrelationPipeline
from store.memory_store import default_alert_store, MemoryAlertStore

router = APIRouter(prefix="/api/v1")


class DetectionResponse(BaseModel):
    window_id: str
    verdicts_count: int
    alerts_generated: int
    verdicts: List[DetectionVerdict]
    alerts: List[AlertV1]


class ActiveConnectionManager:
    """Manages active WebSocket connections for live alert broadcasting."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_alert(self, alert: AlertV1):
        dead_connections = []
        payload = alert.model_dump(mode="json")
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = ActiveConnectionManager()


@router.post("/detect", response_model=DetectionResponse)
async def process_window(window: WindowData):
    """Ingests a feature window, executes DET0 and DET1 concurrently, and computes Phase 8 alerts."""
    # 1. Evaluate DET0 and DET1 in parallel
    verdicts = await default_orchestrator.evaluate_async(window)

    # 2. Correlate, fuse via Noisy-OR with evidence discount, and score severity
    alerts = default_correlation_pipeline.process_window(window, verdicts)

    # 3. Store in append-only store and broadcast to WebSocket dashboard listeners
    for alert in alerts:
        stored_alert, is_new = default_alert_store.insert(alert)
        if is_new:
            await ws_manager.broadcast_alert(stored_alert)

    return DetectionResponse(
        window_id=window.window_id,
        verdicts_count=len(verdicts),
        alerts_generated=len(alerts),
        verdicts=verdicts,
        alerts=alerts,
    )


@router.get("/alerts", response_model=List[AlertV1])
def list_alerts(
    threat_class: Optional[ThreatClass] = Query(None, description="Filter by threat family"),
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity level"),
    subject_key: Optional[str] = Query(None, description="Filter by entity IP or identifier"),
    limit: int = Query(50, ge=1, le=500),
):
    """Retrieves alerts with filtering, sorted newest first."""
    return default_alert_store.query(
        threat_class=threat_class,
        severity=severity,
        subject_key=subject_key,
        limit=limit,
    )


@router.get("/alerts/{alert_id}", response_model=AlertV1)
def get_alert_by_id(alert_id: str):
    """Retrieves single alert with complete contributing evidence and raw impact audit."""
    alert = default_alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")
    return alert


@router.get("/detectors", response_model=List[Dict[str, Any]])
def list_detectors():
    """Returns manifest of all active detectors, versions, calibrators, and mock status."""
    return default_registry.get_manifest()


@router.get("/health")
def health_check():
    """System health check and cryptographic store audit status."""
    ledger_intact = default_alert_store.verify_ledger_integrity()
    return {
        "status": "healthy" if ledger_intact else "degraded",
        "active_detectors": len(default_registry.list_all()),
        "total_stored_alerts": default_alert_store.count(),
        "ledger_cryptographic_chain_valid": ledger_intact,
    }
