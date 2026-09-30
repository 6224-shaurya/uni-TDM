"""Base detector abstract contract and calibrator components per SAD v2.0 §8."""

from abc import ABC, abstractmethod
import math
from typing import Dict, List, Optional, Any, Tuple
from schemas.features import FeatureVector, WindowData
from schemas.verdict import DetectionVerdict
from schemas.threats import ThreatClass, DetectorFamily, PriorityTag, SubjectType


class BaseCalibrator(ABC):
    """Abstract interface for probability calibrators (Platt, Isotonic, ECDF)."""

    @abstractmethod
    def calibrate(self, raw_score: float) -> float:
        """Transforms uncalibrated raw model output to calibrated probability in [0.0, 1.0]."""
        pass


class PlattCalibrator(BaseCalibrator):
    """Logistic sigmoid calibration: P(y=1|s) = 1 / (1 + exp(A*s + B)).
    
    Standard for margin-based classifiers and linear boundaries.
    """

    def __init__(self, a: float = -1.0, b: float = 0.0):
        self.a = a
        self.b = b

    def calibrate(self, raw_score: float) -> float:
        try:
            val = self.a * raw_score + self.b
            # Numerical clamp to prevent overflow in exp
            val = max(min(val, 60.0), -60.0)
            return 1.0 / (1.0 + math.exp(val))
        except OverflowError:
            return 1.0 if (self.a * raw_score + self.b) < 0 else 0.0


class IsotonicCalibrator(BaseCalibrator):
    """Piecewise linear / step calibration for tree ensembles (GBDT, Random Forest)."""

    def __init__(self, thresholds: List[Tuple[float, float]]):
        """thresholds: List of (raw_score_cutoff, calibrated_prob), sorted ascending."""
        self.thresholds = sorted(thresholds, key=lambda x: x[0])

    def calibrate(self, raw_score: float) -> float:
        if not self.thresholds:
            return max(0.0, min(1.0, raw_score))
        
        if raw_score <= self.thresholds[0][0]:
            return self.thresholds[0][1]
        if raw_score >= self.thresholds[-1][0]:
            return self.thresholds[-1][1]

        # Linear interpolation between adjacent breakpoints
        for i in range(len(self.thresholds) - 1):
            x0, y0 = self.thresholds[i]
            x1, y1 = self.thresholds[i + 1]
            if x0 <= raw_score <= x1:
                if x1 == x0:
                    return y0
                t = (raw_score - x0) / (x1 - x0)
                return y0 + t * (y1 - y0)

        return self.thresholds[-1][1]


class ECDFCalibrator(BaseCalibrator):
    """Empirical Percentile Rank (ECDF) for anomaly detectors (IsolationForest, LOF).
    
    Raw anomaly scores are ranked against a reference benign empirical distribution.
    """

    def __init__(self, reference_quantiles: Optional[List[float]] = None):
        # Default 10 reference quantile checkpoints [0th percentile ... 100th percentile]
        self.reference_quantiles = reference_quantiles or [
            -0.8, -0.6, -0.4, -0.2, 0.0, 0.2, 0.4, 0.6, 0.8, 1.0
        ]

    def calibrate(self, raw_score: float) -> float:
        if raw_score <= 0.0:
            return 0.0
        n = len(self.reference_quantiles)
        if n == 0:
            return 0.5
        # Count how many reference values raw_score exceeds
        count = sum(1 for q in self.reference_quantiles if raw_score >= q)
        prob = count / float(n)
        return max(0.0, min(1.0, prob))


class BaseDetector(ABC):
    """Universal abstract base class for all detection tier algorithms.
    
    Exposes identical .predict() and .calibrate() signatures whether wrapping
    an onnxruntime batch model, scikit-learn ensemble, or river online model.
    """

    def __init__(
        self,
        detector_id: str,
        detector_family: DetectorFamily,
        threat_class: ThreatClass,
        calibrator: BaseCalibrator,
        model_version: str = "1.0.0-mock",
        model_sha256: Optional[str] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        shared_evidence_domain: str = "general",
        alert_threshold: float = 0.50,
    ):
        self.detector_id = detector_id
        self.detector_family = detector_family
        self.threat_class = threat_class
        self.calibrator = calibrator
        self.model_version = model_version
        self.model_sha256 = model_sha256
        self.shared_evidence_domain = shared_evidence_domain
        self.alert_threshold = alert_threshold

    @abstractmethod
    def predict(self, features: FeatureVector) -> float:
        """Infers the raw detection score from input features.
        
        Must be purely mathematical and model-dependent:
        - Classification: decision function / margin / logit / raw ensemble vote
        - Anomaly detection: distance / isolation score / spectral power
        """
        pass

    def calibrate(self, raw_score: float) -> float:
        """Converts raw prediction score into well-calibrated confidence in [0.0, 1.0]."""
        return self.calibrator.calibrate(raw_score)

    @abstractmethod
    def extract_evidence(self, features: FeatureVector, raw_score: float) -> Dict[str, Any]:
        """Extracts explainable evidence features responsible for this detection."""
        pass

    def evaluate(self, window: WindowData) -> DetectionVerdict:
        """Template execution method: runs prediction, calibration, and wraps common envelope."""
        raw_score = self.predict(window.features)
        calibrated_conf = self.calibrate(raw_score)
        evidence = self.extract_evidence(window.features, raw_score)
        
        is_alert_worthy = calibrated_conf >= self.alert_threshold

        return DetectionVerdict(
            detector_id=self.detector_id,
            detector_family=self.detector_family,
            threat_class=self.threat_class,
            subject_type=window.subject_type,
            subject_key=window.subject_key,
            window_id=window.window_id,
            window_start=window.window_start,
            window_end=window.window_end,
            raw_score=round(raw_score, 4),
            calibrated_confidence=round(calibrated_conf, 4),
            priority_tag=PriorityTag.P2_ELEVATED if is_alert_worthy else PriorityTag.P3_NORMAL,
            is_alert_worthy=is_alert_worthy,
            evidence_features=evidence,
            shared_evidence_domain=self.shared_evidence_domain,
            model_version=self.model_version,
            model_sha256=self.model_sha256,
        )
