"""Persistencia del escaneo en Postgres (Supabase) con los modelos de la base."""

import logging
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models.models import Finding, FindingStatus, Scan, ScanStatus
from app.orchestrator.pipeline import ScanResult
from app.orchestrator.triage import TriageResult

logger = logging.getLogger(__name__)


class SqlScanStore:
    """Actualiza la fila del escaneo que creó la API y guarda sus hallazgos.

    Cada método es una transacción: si algo falla, no quedan hallazgos a medias.
    """

    def __init__(self, session_factory: Callable[[], Session] | None = None):
        if session_factory is None:
            from app.models.database import SessionLocal

            session_factory = SessionLocal
        self._session_factory = session_factory

    def mark_running(self, scan_id: str) -> None:
        with self._session_factory() as session, session.begin():
            scan = _get_scan(session, scan_id)
            if scan is not None:
                scan.status = ScanStatus.RUNNING
                scan.started_at = _now()
                scan.error = None

    def save_result(self, scan_id: str, commit_sha: str, result: ScanResult) -> None:
        with self._session_factory() as session, session.begin():
            scan = _get_scan(session, scan_id)
            if scan is None:
                return
            # Un reintento pudo haber guardado hallazgos antes de fallar: se reemplazan.
            session.execute(delete(Finding).where(Finding.scan_id == scan.id))
            session.add_all(
                Finding(
                    scan_id=scan.id,
                    fingerprint=fingerprint,
                    engine=finding.engine,
                    rule_id=finding.rule_id,
                    title=_clean(finding.title),
                    severity=finding.severity,
                    file_path=_clean(finding.file_path),
                    line=finding.line,
                    snippet=_clean(finding.snippet),
                    description=_clean(finding.description),
                    cwe=finding.cwe,
                    cve=finding.cve,
                    metadata_=_clean(finding.metadata),
                    status=FindingStatus.OPEN,
                    **_triage_columns(result.triage.get(fingerprint)),
                )
                for fingerprint, finding in result.findings.items()
            )
            scan.status = ScanStatus.COMPLETED
            scan.commit_sha = commit_sha
            scan.risk_score = result.risk_score
            scan.grade = result.grade
            scan.engine_errors = _clean(result.errors) or None
            scan.error = None
            scan.finished_at = _now()

    def mark_failed(self, scan_id: str, error: str) -> None:
        with self._session_factory() as session, session.begin():
            scan = _get_scan(session, scan_id)
            if scan is not None:
                scan.status = ScanStatus.FAILED
                scan.error = _clean(error)
                scan.finished_at = _now()


def _triage_columns(evaluation: TriageResult | None) -> dict:
    """Columnas ai_* del hallazgo; vacías si la IA no lo evaluó."""
    if evaluation is None:
        return {}
    return {
        "ai_is_false_positive": evaluation.is_false_positive,
        "ai_adjusted_severity": evaluation.adjusted_severity,
        "ai_explanation": _clean(evaluation.explanation),
        "ai_remediation": _clean(evaluation.remediation),
    }


def _get_scan(session: Session, scan_id: str) -> Scan | None:
    """La fila del escaneo, o None si no existe: no tiene sentido reintentar."""
    try:
        key = uuid.UUID(scan_id)
    except ValueError:
        key = None
    scan = session.get(Scan, key) if key else None
    if scan is None:
        logger.warning("El escaneo %s no existe en la base: no se guarda el resultado", scan_id)
    return scan


def _clean(value):
    """Quita el byte nulo, que Postgres no acepta en textos ni en JSONB.

    Los textos salen del código del repo: un archivo con ese carácter no puede
    hacer fallar el guardado de todo el escaneo.
    """
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {_clean(key): _clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


def _now() -> datetime:
    return datetime.now(timezone.utc)
