"""In-memory alert store with idempotency enforcement and SHA-256 hash chaining prototype."""

import hashlib
import json
import threading
from typing import List, Optional, Dict
from schemas.alert import AlertV1
from schemas.threats import ThreatClass, SeverityLevel


class MemoryAlertStore:
    """Thread-safe alert store with idempotency deduplication and SHA-256 ledger chaining."""

    def __init__(self):
        self._lock = threading.RLock()
        self._alerts_by_id: Dict[str, AlertV1] = {}
        self._alerts_by_idempotency: Dict[str, AlertV1] = {}
        self._ledger: List[Dict[str, str]] = []  # [{ "alert_id": ..., "prev_hash": ..., "hash": ... }]
        self._latest_chain_hash: str = "0" * 64

    def insert(self, alert: AlertV1) -> tuple[AlertV1, bool]:
        """Inserts an alert. If idempotency key already exists, updates or collapses duplicate.
        
        Returns:
            (inserted_or_existing_alert, is_new: bool)
        """
        with self._lock:
            if alert.idempotency_key in self._alerts_by_idempotency:
                # Deduplicated: already processed this subject+threat+window
                return self._alerts_by_idempotency[alert.idempotency_key], False

            # Hash chaining for append-only audit verification
            block_content = f"{self._latest_chain_hash}|{alert.alert_id}|{alert.idempotency_key}|{alert.fused_confidence}"
            current_hash = hashlib.sha256(block_content.encode("utf-8")).hexdigest()
            
            self._ledger.append({
                "alert_id": alert.alert_id,
                "prev_hash": self._latest_chain_hash,
                "chain_hash": current_hash,
            })
            self._latest_chain_hash = current_hash

            self._alerts_by_id[alert.alert_id] = alert
            self._alerts_by_idempotency[alert.idempotency_key] = alert
            return alert, True

    def query(
        self,
        threat_class: Optional[ThreatClass] = None,
        severity: Optional[SeverityLevel] = None,
        subject_key: Optional[str] = None,
        limit: int = 50,
    ) -> List[AlertV1]:
        """Queries stored alerts with optional filtering, sorted by created_at descending."""
        with self._lock:
            results = list(self._alerts_by_id.values())

            if threat_class:
                results = [a for a in results if a.threat_class == threat_class]
            if severity:
                results = [a for a in results if a.severity == severity]
            if subject_key:
                results = [a for a in results if a.subject_key == subject_key]

            # Sort latest first
            results.sort(key=lambda x: x.created_at, reverse=True)
            return results[:limit]

    def get_by_id(self, alert_id: str) -> Optional[AlertV1]:
        with self._lock:
            return self._alerts_by_id.get(alert_id)

    def verify_ledger_integrity(self) -> bool:
        """Verifies the SHA-256 cryptographic chain of all stored alerts."""
        with self._lock:
            prev = "0" * 64
            for entry in self._ledger:
                alert = self._alerts_by_id.get(entry["alert_id"])
                if not alert:
                    return False
                expected_content = f"{prev}|{alert.alert_id}|{alert.idempotency_key}|{alert.fused_confidence}"
                expected_hash = hashlib.sha256(expected_content.encode("utf-8")).hexdigest()
                if entry["chain_hash"] != expected_hash:
                    return False
                prev = expected_hash
            return True

    def count(self) -> int:
        with self._lock:
            return len(self._alerts_by_id)


# Global alert store
default_alert_store = MemoryAlertStore()
