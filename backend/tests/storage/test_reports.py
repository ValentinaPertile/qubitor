import json
import os
import uuid

import pytest

from app.engines.base import Finding, Severity
from app.orchestrator.pipeline import ScanResult
from app.storage.reports import (
    ReportStorage,
    archive_scan,
    build_cbom,
    build_report,
    get_report_storage,
    report_key,
)


class ErrorS3(Exception):
    """Imita el ClientError de botocore: trae el código HTTP en `response`."""

    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.response = {"ResponseMetadata": {"HTTPStatusCode": status}, "Error": {"Code": str(status)}}


class S3Falso:
    """Bucket en memoria con la parte de la API de boto3 que se usa."""

    def __init__(self, falla_al_subir=False):
        self.objetos = {}
        self.falla_al_subir = falla_al_subir

    def put_object(self, Bucket, Key, Body, ContentType, ContentDisposition):
        if self.falla_al_subir:
            raise ErrorS3(500)
        self.objetos[(Bucket, Key)] = {"body": Body, "type": ContentType, "disposition": ContentDisposition}

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objetos:
            raise ErrorS3(404)
        return {}

    def generate_presigned_url(self, ClientMethod, Params, ExpiresIn):
        return f"https://bucket.test/{Params['Key']}?method={ClientMethod}&expires={ExpiresIn}"


def _hallazgo(engine, rule_id, severity, file_path, line, algorithm=None):
    return Finding(
        engine=engine, rule_id=rule_id, title=f"Título de {rule_id}", severity=severity,
        file_path=file_path, line=line, snippet="...", description="...",
        metadata={"algorithm": algorithm} if algorithm else {},
    )


def _resultado():
    hallazgos = [
        _hallazgo("crypto", "crypto.pqc.rsa-keygen", Severity.MEDIUM, "app/keys.py", 10, "RSA"),
        _hallazgo("crypto", "crypto.pqc.inventory.hash", Severity.INFO, "app/keys.py", 25, "SHA-256"),
        _hallazgo("crypto", "crypto.pqc.ecdsa", Severity.MEDIUM, "app/signing.js", 5, "ECDSA"),
        _hallazgo("sca", "sca.osv.GHSA-x84v-xcm2-53pg", Severity.HIGH, "requirements.txt", 1),
    ]
    return ScanResult(
        findings={f"fp{i}": h for i, h in enumerate(hallazgos)},
        errors={"secrets": "TimeoutError"},
        risk_score=89.0,
        grade="B",
        duration_seconds=3.2,
        engine_count=4,
    )


def test_el_reporte_tiene_el_resultado_completo():
    reporte = build_report("scan1", "https://github.com/org/repo", "abc123", _resultado())

    assert reporte["risk_score"] == 89.0
    assert reporte["grade"] == "B"
    assert reporte["commit_sha"] == "abc123"
    assert reporte["engine_errors"] == {"secrets": "TimeoutError"}
    assert reporte["summary"] == {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 1}
    assert len(reporte["findings"]) == 4
    assert reporte["findings"][0]["fingerprint"] == "fp0"
    assert reporte["findings"][0]["severity"] == "medium"
    # Tiene que poder guardarse como JSON tal cual.
    json.dumps(reporte)


def test_el_cbom_es_cyclonedx_con_solo_la_criptografia():
    cbom = build_cbom("scan1", "https://github.com/org/repo", "abc123", _resultado())

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert [c["name"] for c in cbom["components"]] == ["ECDSA", "RSA", "SHA-256"]


def test_guarda_el_reporte_y_el_cbom_como_descarga():
    s3 = S3Falso()

    assert archive_scan("scan1", "url", "sha", _resultado(), storage=ReportStorage(s3, "qubitor")) is True

    assert set(s3.objetos) == {("qubitor", "reports/scan1/report.json"), ("qubitor", "reports/scan1/cbom.json")}
    reporte = s3.objetos[("qubitor", "reports/scan1/report.json")]
    assert reporte["type"].startswith("application/json")
    assert reporte["disposition"] == 'attachment; filename="qubitor-scan1-report.json"'
    assert json.loads(reporte["body"])["scan_id"] == "scan1"
    cbom = s3.objetos[("qubitor", "reports/scan1/cbom.json")]
    assert cbom["type"].startswith("application/vnd.cyclonedx+json")
    assert cbom["disposition"] == 'attachment; filename="qubitor-scan1-cbom.cdx.json"'
    assert json.loads(cbom["body"])["bomFormat"] == "CycloneDX"


def test_url_firmada_que_vence():
    storage = ReportStorage(S3Falso(), "qubitor")
    storage.save("scan1", "report", {"ok": True})

    url = storage.signed_url("scan1", "report")

    assert url == "https://bucket.test/reports/scan1/report.json?method=get_object&expires=600"


def test_sin_reporte_guardado_no_hay_url():
    assert ReportStorage(S3Falso(), "qubitor").signed_url("scan1", "cbom") is None


def test_otro_error_del_bucket_no_se_confunde_con_que_falte_el_archivo():
    s3 = S3Falso()
    s3.head_object = lambda **kwargs: (_ for _ in ()).throw(ErrorS3(403))

    with pytest.raises(ErrorS3):
        ReportStorage(s3, "qubitor").signed_url("scan1", "report")


def test_si_el_bucket_falla_el_escaneo_no_se_rompe(caplog):
    storage = ReportStorage(S3Falso(falla_al_subir=True), "qubitor")

    assert archive_scan("scan1", "url", "sha", _resultado(), storage=storage) is False
    assert "no se pudo guardar el reporte" in caplog.text


def test_sin_variables_de_r2_no_guarda_nada(monkeypatch):
    for variable in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET", "R2_ENDPOINT"):
        monkeypatch.delenv(variable, raising=False)

    assert get_report_storage() is None
    assert archive_scan("scan1", "url", "sha", _resultado()) is False


def test_con_las_variables_arma_el_cliente_de_r2(monkeypatch):
    monkeypatch.delenv("R2_ENDPOINT", raising=False)
    monkeypatch.setenv("R2_ACCOUNT_ID", "cuenta123")
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "clave-falsa")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "secreto-falso")
    monkeypatch.setenv("R2_BUCKET", "qubitor-reportes")

    storage = get_report_storage()

    assert storage.bucket == "qubitor-reportes"
    assert storage.client.meta.endpoint_url == "https://cuenta123.r2.cloudflarestorage.com"


@pytest.mark.parametrize("scan_id", ["../otro", "a/b", "", "x" * 65])
def test_rechaza_ids_que_arman_otra_ruta_en_el_bucket(scan_id):
    with pytest.raises(ValueError):
        report_key(scan_id, "report")


def test_rechaza_tipos_de_reporte_desconocidos():
    with pytest.raises(ValueError):
        report_key("scan1", "secretos")


@pytest.mark.skipif(os.environ.get("QUBITOR_TESTS_BUCKET") != "1",
                    reason="usa un bucket real; correr con QUBITOR_TESTS_BUCKET=1 y las variables R2_*")
def test_contra_un_bucket_real_sube_y_descarga_con_la_url_firmada():
    import urllib.request

    storage = get_report_storage()
    scan_id = f"test-{uuid.uuid4()}"

    assert archive_scan(scan_id, "url", "sha", _resultado(), storage=storage) is True
    with urllib.request.urlopen(storage.signed_url(scan_id, "cbom", expires=60)) as respuesta:
        assert [c["name"] for c in json.load(respuesta)["components"]] == ["ECDSA", "RSA", "SHA-256"]
    storage.client.delete_object(Bucket=storage.bucket, Key=report_key(scan_id, "report"))
    storage.client.delete_object(Bucket=storage.bucket, Key=report_key(scan_id, "cbom"))
