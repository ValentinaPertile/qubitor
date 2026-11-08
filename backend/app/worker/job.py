"""Trabajo que ejecuta el scan-worker para cada escaneo de la cola."""

import os
import tempfile

from rq import get_current_job

from app.engines.base import Engine
from app.engines.crypto import CryptoEngine
from app.engines.sast import SastEngine
from app.engines.sca import ScaEngine
from app.engines.secrets.engine import SecretsEngine
from app.orchestrator.pipeline import ScanResult, analyze_repository
from app.orchestrator.triage import load_provider
from app.storage import archive_scan
from app.worker.clone import CloneRejected, clone_repository, remove_tree
from app.worker.progress import report_stage
from app.worker.store import get_store


def default_engines() -> list[Engine]:
    return [SastEngine(), ScaEngine(), SecretsEngine(), CryptoEngine()]


def run_scan(scan_id: str, repo_url: str) -> dict:
    """Clona el repo, lo analiza, guarda el resultado y borra el clon.

    Devuelve un resumen, que RQ conserva como resultado del trabajo. Lo que no
    se va a arreglar reintentando termina acá; una falla transitoria se relanza
    para que RQ reintente, y queda como fallido recién en el último intento.
    """
    store = get_store()
    store.mark_running(scan_id)
    workdir = tempfile.mkdtemp(prefix=f"scan-{scan_id}-", dir=os.getenv("REPOS_DIR"))
    try:
        repo_path = os.path.join(workdir, "repo")
        report_stage("clone")
        commit_sha = clone_repository(repo_url, repo_path)
        result = analyze_repository(repo_path, default_engines(), on_stage=report_stage, triage=load_provider())
        if result.failed:
            store.mark_failed(scan_id, "Fallaron todos los motores")
            return _summary("failed", result=result)
        report_stage("persist")
        store.save_result(scan_id, commit_sha, result)
        # Reporte y CBOM en R2 (Módulo D). Si el bucket falla no lanza: el escaneo ya quedó guardado.
        archive_scan(scan_id, repo_url, commit_sha, result)
        return _summary("completed", result=result, commit_sha=commit_sha)
    except CloneRejected as error:
        store.mark_failed(scan_id, str(error))
        return _summary("failed", error=str(error))
    except Exception as error:
        if _is_last_attempt():
            store.mark_failed(scan_id, f"{type(error).__name__}: {error}")
        raise
    finally:
        remove_tree(workdir)


def _is_last_attempt() -> bool:
    job = get_current_job()
    return job is None or not job.retries_left


def _summary(
    status: str,
    result: ScanResult | None = None,
    commit_sha: str | None = None,
    error: str | None = None,
) -> dict:
    summary: dict = {"status": status, "commit_sha": commit_sha, "error": error}
    if result is not None:
        summary |= {
            "findings": len(result.findings),
            "risk_score": result.risk_score,
            "grade": result.grade,
            "engine_errors": result.errors,
            "duration_seconds": result.duration_seconds,
        }
    return summary
