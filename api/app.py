"""FastAPI backend application for SIH26145 AI Threat Detection Engine."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router, ws_manager
from det1.engine import default_orchestrator


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: detectors initialized via imports
    yield
    # Shutdown: clean up background thread pools
    default_orchestrator.shutdown()


def create_app() -> FastAPI:
    """Factory creating configured FastAPI app instance."""
    app = FastAPI(
        title="SIH26145 Cyber Threat Detection Engine",
        description=(
            "Backend detection tier (Phase 7) and correlation, fusion & severity engine (Phase 8) "
            "for unidirectional IP network traffic."
        ),
        version="2.0.0",
        lifespan=lifespan,
    )

    # Enable CORS for local web dashboard and dev servers
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)

    @app.websocket("/ws/alerts")
    async def websocket_alerts(websocket: WebSocket):
        """Streaming alert feed for the Phase 10 dashboard."""
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep-alive loop receiving client pings
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)

    return app


app = create_app()
