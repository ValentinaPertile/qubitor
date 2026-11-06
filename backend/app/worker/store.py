"""Persistencia del resultado de un escaneo, vista desde el scan-worker.

El worker solo conoce esta interfaz. `LogScanStore` deja el pipeline andando
mientras no estén los modelos: cuando se mergeen, se agrega la implementación
con SQLAlchemy y se cambia `get_store`, sin tocar la cola ni el job.
"""

import logging
from typing import Protocol

from app.orchestrator.pipeline import ScanResult

logger = logging.getLogger(__name__)


class ScanStore(Protocol):
    def mark_running(self, scan_id: str) -> None: ...

    def save_result(self, scan_id: str, commit_sha: str, result: ScanResult) -> None: ...

    def mark_failed(self, scan_id: str, error: str) -> None: ...


class LogScanStore:
    """Registra los resultados en el log, sin guardarlos."""

    def mark_running(self, scan_id: str) -> None:
        logger.info("Escaneo %s: en curso", scan_id)

    def save_result(self, scan_id: str, commit_sha: str, result: ScanResult) -> None:
        logger.info(
            "Escaneo %s: %d hallazgos, score %s, nota %s (commit %s)",
            scan_id, len(result.findings), result.risk_score, result.grade, commit_sha,
        )

    def mark_failed(self, scan_id: str, error: str) -> None:
        logger.warning("Escaneo %s: falló: %s", scan_id, error)


def get_store() -> ScanStore:
    return LogScanStore()
