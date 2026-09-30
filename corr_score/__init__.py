"""Correlation, fusion, and severity scoring package (Phase 8)."""

from corr_score.idempotency import generate_idempotency_key
from corr_score.fusion import NoisyORFusionEngine, default_fusion_engine
from corr_score.severity import ScoreEngine, default_score_engine
from corr_score.pipeline import CorrelationPipeline, default_correlation_pipeline

__all__ = [
    "generate_idempotency_key",
    "NoisyORFusionEngine",
    "default_fusion_engine",
    "ScoreEngine",
    "default_score_engine",
    "CorrelationPipeline",
    "default_correlation_pipeline",
]
