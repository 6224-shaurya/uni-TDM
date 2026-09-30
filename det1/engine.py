"""Detection tier orchestrator executing DET0 and DET1 banks in parallel."""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
from schemas.features import WindowData
from schemas.verdict import DetectionVerdict
from det0.annotator import FastPathAnnotator, default_annotator
from det1.registry import DetectorRegistry, default_registry

logger = logging.getLogger(__name__)


class DetectionTierOrchestrator:
    """Coordinates concurrent evaluation of DET0 fast-path and DET1 deep detector bank."""

    def __init__(
        self,
        annotator: Optional[FastPathAnnotator] = None,
        registry: Optional[DetectorRegistry] = None,
        max_workers: int = 8,
    ):
        self.annotator = annotator or default_annotator
        self.registry = registry or default_registry
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="det_tier")

    def evaluate_sync(self, window: WindowData) -> List[DetectionVerdict]:
        """Synchronously runs DET0 and all DET1 detectors."""
        verdicts: List[DetectionVerdict] = []

        # 1. Run DET0 Fast-Path annotator
        try:
            v0 = self.annotator.annotate(window)
            verdicts.append(v0)
        except Exception as e:
            logger.error(f"Error evaluating DET0 fast-path: {e}", exc_info=True)

        # 2. Run DET1 detectors
        for detector in self.registry.list_all():
            try:
                v1 = detector.evaluate(window)
                verdicts.append(v1)
            except Exception as e:
                logger.error(f"Error evaluating detector {detector.detector_id}: {e}", exc_info=True)

        return verdicts

    async def evaluate_async(self, window: WindowData) -> List[DetectionVerdict]:
        """Asynchronously fans out DET0 and DET1 across worker pool in parallel."""
        loop = asyncio.get_running_loop()
        tasks = []

        # Fan-out DET0
        tasks.append(loop.run_in_executor(self.executor, self.annotator.annotate, window))

        # Fan-out DET1 detectors
        for detector in self.registry.list_all():
            tasks.append(loop.run_in_executor(self.executor, detector.evaluate, window))

        # Gather all verdicts concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        verdicts: List[DetectionVerdict] = []
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"Detector task error: {res}")
            elif isinstance(res, DetectionVerdict):
                verdicts.append(res)

        return verdicts

    def shutdown(self) -> None:
        """Shuts down worker pool."""
        self.executor.shutdown(wait=False)


# Global default orchestrator
default_orchestrator = DetectionTierOrchestrator()
