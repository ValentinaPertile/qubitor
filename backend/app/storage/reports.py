"""Reportes de cada escaneo en un bucket S3-compatible (Cloudflare R2) (Módulo D).

Al terminar un escaneo se guardan dos archivos JSON:

- `reports/<scan_id>/report.json`: el resultado completo (Risk Score y hallazgos).
- `reports/<scan_id>/cbom.json`: el inventario criptográfico (CBOM) en formato
  CycloneDX 1.6, solo los hallazgos del motor de criptografía.

El bucket es privado: la interfaz los descarga con URLs firmadas que vencen.
Sin las variables `R2_*` no se guarda nada y el escaneo sigue igual, como el
worker sin `DATABASE_URL`.
"""

import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

from app.engines.base import Finding, Severity
from app.orchestrator.pipeline import ScanResult
from app.storage.cyclonedx import build_cyclonedx

logger = logging.getLogger(__name__)

ReportKind = Literal["report", "cbom"]
REPORT_KINDS: tuple[ReportKind, ...] = ("report", "cbom")

# Tipo de contenido y nombre con el que se descarga cada archivo.
_CONTENT_TYPES = {"report": "application/json", "cbom": "application/vnd.cyclonedx+json"}
_FILE_NAMES = {"report": "report.json", "cbom": "cbom.cdx.json"}

# Lo que dura una URL firmada. Corto: alcanza para descargar, no para compartir.
SIGNED_URL_SECONDS = 10 * 60

# Los ids de escaneo son UUID; esto evita que uno raro arme otra ruta en el bucket.
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class S3Client(Protocol):
    """Lo que se usa del cliente de boto3. Los tests pasan uno falso."""

    def put_object(self, **kwargs: Any) -> Any: ...

    def head_object(self, **kwargs: Any) -> Any: ...

    def generate_presigned_url(self, ClientMethod: str, Params: dict, ExpiresIn: int) -> str: ...


def build_report(scan_id: str, repo_url: str, commit_sha: str, result: ScanResult) -> dict:
    findings = [_finding_dict(fp, finding) for fp, finding in result.findings.items()]
    by_severity = Counter(finding.severity.value for finding in result.findings.values())
    return {
        "scan_id": scan_id,
        "repository_url": repo_url,
        "commit_sha": commit_sha,
        "generated_at": _now(),
        "risk_score": result.risk_score,
        "grade": result.grade,
        "duration_seconds": result.duration_seconds,
        "engine_errors": result.errors,
        "summary": {severity.value: by_severity.get(severity.value, 0) for severity in Severity},
        "findings": findings,
    }


def build_cbom(scan_id: str, repo_url: str, commit_sha: str, result: ScanResult) -> dict:
    """Inventario criptográfico en CycloneDX 1.6: todo uso de criptografía, también el seguro."""
    return build_cyclonedx(scan_id, repo_url, commit_sha, result.findings)


class ReportStorage:
    def __init__(self, client: S3Client, bucket: str):
        self.client = client
        self.bucket = bucket

    def save(self, scan_id: str, kind: ReportKind, content: dict) -> None:
        self.client.put_object(
            Bucket=self.bucket,
            Key=report_key(scan_id, kind),
            Body=json.dumps(content, ensure_ascii=False, indent=2).encode("utf-8"),
            ContentType=f"{_CONTENT_TYPES[kind]}; charset=utf-8",
            # Al abrir la URL firmada el navegador descarga el archivo con este nombre.
            ContentDisposition=f'attachment; filename="qubitor-{scan_id}-{_FILE_NAMES[kind]}"',
        )

    def signed_url(self, scan_id: str, kind: ReportKind, expires: int = SIGNED_URL_SECONDS) -> str | None:
        """URL para descargar el archivo, o None si ese escaneo no lo tiene."""
        key = report_key(scan_id, kind)
        if not self._exists(key):
            return None
        return self.client.generate_presigned_url(
            "get_object", Params={"Bucket": self.bucket, "Key": key}, ExpiresIn=expires
        )

    def _exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except Exception as error:
            if _status_code(error) == 404:
                return False
            raise
        return True


def report_key(scan_id: str, kind: ReportKind) -> str:
    if not _SAFE_ID.match(scan_id):
        raise ValueError(f"Id de escaneo inválido: {scan_id!r}")
    if kind not in REPORT_KINDS:
        raise ValueError(f"Tipo de reporte inválido: {kind!r}")
    return f"reports/{scan_id}/{kind}.json"


def get_report_storage() -> ReportStorage | None:
    """El almacenamiento configurado por variables de entorno, o None si falta alguna."""
    account_id = os.getenv("R2_ACCOUNT_ID")
    access_key = os.getenv("R2_ACCESS_KEY_ID")
    secret_key = os.getenv("R2_SECRET_ACCESS_KEY")
    bucket = os.getenv("R2_BUCKET")
    # R2_ENDPOINT permite probar con otro servicio S3-compatible (por ejemplo MinIO en local).
    endpoint = os.getenv("R2_ENDPOINT") or (account_id and f"https://{account_id}.r2.cloudflarestorage.com")
    if not (endpoint and access_key and secret_key and bucket):
        return None

    # Se importa acá: sin R2 configurado, la API y el worker no cargan boto3.
    import boto3
    from botocore.config import Config

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="auto",
        config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
    )
    return ReportStorage(client, bucket)


def archive_scan(scan_id: str, repo_url: str, commit_sha: str, result: ScanResult,
                 storage: ReportStorage | None = None) -> bool:
    """Guarda el reporte y el CBOM del escaneo. Devuelve True si se guardaron.

    No lanza excepciones: si el bucket falla, el escaneo ya está en la base y
    no tiene que quedar como fallido por eso. Solo se registra en el log.
    """
    storage = storage or get_report_storage()
    if storage is None:
        return False
    try:
        storage.save(scan_id, "report", build_report(scan_id, repo_url, commit_sha, result))
        storage.save(scan_id, "cbom", build_cbom(scan_id, repo_url, commit_sha, result))
    except Exception:
        logger.exception("Escaneo %s: no se pudo guardar el reporte en el bucket", scan_id)
        return False
    return True


def _finding_dict(fp: str, finding: Finding) -> dict:
    return {
        "fingerprint": fp,
        "engine": finding.engine,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "file_path": finding.file_path,
        "line": finding.line,
        "snippet": finding.snippet,
        "description": finding.description,
        "cwe": finding.cwe,
        "cve": finding.cve,
        "metadata": finding.metadata,
    }


def _status_code(error: Exception) -> int | None:
    response = getattr(error, "response", None) or {}
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    if status is None and response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
        return 404
    return status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
