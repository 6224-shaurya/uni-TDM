"""Detector registry providing plug-and-play swapping between mock and real models."""

import logging
from typing import Dict, List, Optional, Any
from schemas.threats import ThreatClass
from det1.base import BaseDetector
from det1.mock import (
    MockDDoSDetector,
    MockBeaconingDetector,
    MockDGADetector,
    MockEncryptedMalwareDetector,
    MockReconDetector,
    MockExfiltrationDetector,
)

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """Central registry and lifecycle manager for all DET1 detectors.
    
    Enforces the BaseDetector contract so replacing temporary mock detectors
    with real ONNX or River models requires only registering the new instance.
    """

    def __init__(self, auto_load_mocks: bool = True):
        self._detectors: Dict[str, BaseDetector] = {}
        self._by_threat: Dict[ThreatClass, BaseDetector] = {}
        
        if auto_load_mocks:
            self.load_mock_detectors()

    def load_mock_detectors(self) -> None:
        """Instantiates and registers the default bank of mock detectors for T-a through T-f."""
        self.register(MockDDoSDetector())
        self.register(MockBeaconingDetector())
        self.register(MockDGADetector())
        self.register(MockEncryptedMalwareDetector())
        self.register(MockReconDetector())
        self.register(MockExfiltrationDetector())
        logger.info("Loaded default mock detector bank for T-a through T-f.")

    def register(self, detector: BaseDetector, replace: bool = True) -> None:
        """Registers a detector instance. Replaces existing one for that threat class if replace=True."""
        if not isinstance(detector, BaseDetector):
            raise TypeError(f"Detector must inherit from BaseDetector, got {type(detector)}")

        self._detectors[detector.detector_id] = detector
        self._by_threat[detector.threat_class] = detector
        logger.info(
            f"Registered detector '{detector.detector_id}' for {detector.threat_class.value} "
            f"(family={detector.detector_family.value}, version={detector.model_version})"
        )

    def swap(self, threat_class: ThreatClass, new_detector: BaseDetector) -> BaseDetector:
        """Atomically replaces the active detector for a specific threat class.
        
        This is the primary method used when real ONNX/River models arrive.
        Returns the evicted detector instance.
        """
        if not isinstance(new_detector, BaseDetector):
            raise TypeError(f"New detector must inherit from BaseDetector, got {type(new_detector)}")

        old_detector = self._by_threat.get(threat_class)
        if old_detector:
            self._detectors.pop(old_detector.detector_id, None)

        self.register(new_detector, replace=True)
        logger.info(
            f"Swapped detector for {threat_class.value}: "
            f"evicted '{old_detector.detector_id if old_detector else 'None'}' -> installed '{new_detector.detector_id}'"
        )
        return old_detector

    def get_by_threat(self, threat_class: ThreatClass) -> Optional[BaseDetector]:
        """Retrieves detector by threat class."""
        return self._by_threat.get(threat_class)

    def get_by_id(self, detector_id: str) -> Optional[BaseDetector]:
        """Retrieves detector by its unique detector_id."""
        return self._detectors.get(detector_id)

    def list_all(self) -> List[BaseDetector]:
        """Returns all registered detectors."""
        return list(self._detectors.values())

    def get_manifest(self) -> List[Dict[str, Any]]:
        """Returns inspection manifest of active detectors for health checks and dashboards."""
        manifest = []
        for det in self._detectors.values():
            manifest.append({
                "detector_id": det.detector_id,
                "threat_class": det.threat_class.value,
                "detector_family": det.detector_family.value,
                "calibrator_type": type(det.calibrator).__name__,
                "model_version": det.model_version,
                "model_sha256": det.model_sha256,
                "shared_evidence_domain": det.shared_evidence_domain,
                "alert_threshold": det.alert_threshold,
                "is_mock": "mock" in det.detector_id.lower() or "mock" in det.model_version.lower(),
            })
        return manifest


# Global default registry instance
default_registry = DetectorRegistry(auto_load_mocks=True)
