"""Tests contra un Postgres real.

Se ejecutan con QUBITOR_TEST_DATABASE_URL apuntando a una base descartable, por
ejemplo un contenedor local:

    docker run -d --name qubitor-test-pg -e POSTGRES_PASSWORD=qubitor \\
        -e POSTGRES_DB=qubitor_test -p 127.0.0.1:55432:5432 postgres:16-alpine
    QUBITOR_TEST_DATABASE_URL=postgresql+psycopg://postgres:qubitor@127.0.0.1:55432/qubitor_test
"""

import os
import uuid

import pytest

from app.engines.base import Finding, Severity
from app.orchestrator.pipeline import ScanResult
from app.worker import store as store_module
from app.worker.store import LogScanStore

TEST_DATABASE_URL = os.getenv("QUBITOR_TEST_DATABASE_URL")
necesita_postgres = pytest.mark.skipif(
    not TEST_DATABASE_URL, reason="necesita un Postgres (QUBITOR_TEST_DATABASE_URL)"
)


def test_sin_database_url_usa_el_log(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert isinstance(store_module.get_store(), LogScanStore)


def test_con_database_url_usa_la_base(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:1/x")
    from app.worker.sql_store import SqlScanStore

    assert isinstance(store_module.get_store(), SqlScanStore)


@pytest.fixture
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models.database import Base

    engine = create_engine(TEST_DATABASE_URL)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def scan_id(db):
    from app.models.models import Organization, Repository, Scan

    with db() as session, session.begin():
        org = Organization(name="Qubitor", clerk_org_id="org_1")
        repo = Repository(organization=org, full_name="a/b", url="https://github.com/a/b")
        scan = Scan(repository=repo)
        session.add(scan)
        session.flush()
        return str(scan.id)


def _finding(line, severity=Severity.HIGH, **cambios):
    datos = dict(
        engine="sast", rule_id="sast.bandit.B307", title="Uso de eval()", severity=severity,
        file_path="app/utils.py", line=line, snippet="eval(x)", description="d",
        cwe="CWE-78", metadata={"confidence": "HIGH"},
    )
    datos.update(cambios)
    return Finding(**datos)


def _resultado(*hallazgos, errores=None):
    from app.orchestrator.normalize import deduplicate

    return ScanResult(
        findings=deduplicate(list(hallazgos)), errors=errores or {}, risk_score=90.0,
        grade="A", duration_seconds=1.5, engine_count=2,
    )


def _leer(db, scan_id):
    from app.models.models import Scan

    with db() as session:
        scan = session.get(Scan, uuid.UUID(scan_id))
        hallazgos = sorted(scan.findings, key=lambda f: f.line or 0)
        session.expunge_all()
        return scan, hallazgos


@necesita_postgres
def test_marca_el_escaneo_en_curso(db, scan_id):
    from app.models.models import ScanStatus
    from app.worker.sql_store import SqlScanStore

    SqlScanStore(db).mark_running(scan_id)

    scan, _ = _leer(db, scan_id)
    assert scan.status is ScanStatus.RUNNING
    assert scan.started_at is not None


@necesita_postgres
def test_guarda_el_resultado_y_los_hallazgos(db, scan_id):
    from app.models.models import FindingStatus, ScanStatus
    from app.orchestrator.normalize import fingerprint
    from app.worker.sql_store import SqlScanStore

    primero = _finding(2)
    resultado = _resultado(primero, _finding(5, severity=Severity.LOW), errores={"sca": "timeout"})

    SqlScanStore(db).save_result(scan_id, "a" * 40, resultado)

    scan, hallazgos = _leer(db, scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert (scan.commit_sha, scan.risk_score, scan.grade) == ("a" * 40, 90.0, "A")
    assert scan.engine_errors == {"sca": "timeout"}
    assert scan.finished_at is not None
    assert len(hallazgos) == 2
    guardado = hallazgos[0]
    assert guardado.fingerprint == fingerprint(primero)
    assert guardado.severity is Severity.HIGH
    assert guardado.status is FindingStatus.OPEN
    assert (guardado.cwe, guardado.metadata_) == ("CWE-78", {"confidence": "HIGH"})


@necesita_postgres
def test_severidad_y_estado_se_guardan_por_valor(db, scan_id):
    from sqlalchemy import text

    from app.worker.sql_store import SqlScanStore

    SqlScanStore(db).save_result(scan_id, "a" * 40, _resultado(_finding(2)))

    with db() as session:
        fila = session.execute(text("select severity::text, status::text from findings")).one()
        estado = session.execute(text("select status::text from scans")).scalar_one()
    assert tuple(fila) == ("high", "open")
    assert estado == "completed"


@necesita_postgres
def test_guardar_dos_veces_no_duplica_hallazgos(db, scan_id):
    from app.worker.sql_store import SqlScanStore

    store = SqlScanStore(db)
    store.save_result(scan_id, "a" * 40, _resultado(_finding(2), _finding(3)))
    store.save_result(scan_id, "b" * 40, _resultado(_finding(2)))

    scan, hallazgos = _leer(db, scan_id)
    assert scan.commit_sha == "b" * 40
    assert [h.line for h in hallazgos] == [2]


@necesita_postgres
def test_byte_nulo_de_un_repo_no_rompe_el_guardado(db, scan_id):
    from app.models.models import ScanStatus
    from app.worker.sql_store import SqlScanStore

    # Postgres no acepta el byte nulo en textos ni en JSONB: un archivo del repo
    # con ese carácter no puede hacer fallar el escaneo entero.
    hallazgo = _finding(3, snippet="x\x00y", title="t\x00", metadata={"valor": "a\x00b", "lista": ["\x00"]})

    SqlScanStore(db).save_result(scan_id, "a" * 40, _resultado(hallazgo))

    scan, [guardado] = _leer(db, scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert (guardado.snippet, guardado.title) == ("xy", "t")
    assert guardado.metadata_ == {"valor": "ab", "lista": [""]}


@necesita_postgres
def test_si_falla_al_guardar_no_quedan_hallazgos_a_medias(db, scan_id, monkeypatch):
    from sqlalchemy.orm import Session

    from app.models.models import ScanStatus
    from app.worker.sql_store import SqlScanStore

    original = Session.add_all

    def add_all_y_falla(self, instances):
        original(self, instances)
        self.flush()
        raise RuntimeError("se cortó la conexión")

    monkeypatch.setattr(Session, "add_all", add_all_y_falla)

    with pytest.raises(RuntimeError):
        SqlScanStore(db).save_result(scan_id, "a" * 40, _resultado(_finding(2), _finding(3)))

    monkeypatch.undo()
    scan, hallazgos = _leer(db, scan_id)
    assert scan.status is ScanStatus.QUEUED
    assert hallazgos == []


@necesita_postgres
def test_marca_el_escaneo_fallido(db, scan_id):
    from app.models.models import ScanStatus
    from app.worker.sql_store import SqlScanStore

    SqlScanStore(db).mark_failed(scan_id, "El repo no existe o no es público")

    scan, _ = _leer(db, scan_id)
    assert scan.status is ScanStatus.FAILED
    assert scan.error == "El repo no existe o no es público"
    assert scan.finished_at is not None


@necesita_postgres
@pytest.mark.parametrize("scan_id_raro", [str(uuid.uuid4()), "no-es-un-uuid"])
def test_escaneo_inexistente_no_rompe(db, scan_id_raro):
    from app.worker.sql_store import SqlScanStore

    store = SqlScanStore(db)
    store.mark_running(scan_id_raro)
    store.save_result(scan_id_raro, "a" * 40, _resultado(_finding(2)))
    store.mark_failed(scan_id_raro, "x")


@necesita_postgres
def test_el_job_guarda_el_escaneo_completo_en_la_base(db, scan_id, monkeypatch, tmp_path):
    from pathlib import Path

    from app.engines.base import Engine
    from app.models.models import ScanStatus
    from app.worker import job as job_module
    from app.worker.sql_store import SqlScanStore

    class Motor(Engine):
        name = "sast"

        def scan(self, repo_path):
            return [_finding(1)]

    def clon_falso(url, destino):
        os.makedirs(destino)
        Path(destino, "app.py").write_text("x = 1\n")
        return "c" * 40

    monkeypatch.setattr(job_module, "get_store", lambda: SqlScanStore(db))
    monkeypatch.setattr(job_module, "clone_repository", clon_falso)
    monkeypatch.setattr(job_module, "default_engines", lambda: [Motor()])
    monkeypatch.setenv("REPOS_DIR", str(tmp_path))

    job_module.run_scan(scan_id, "https://github.com/a/b")

    scan, hallazgos = _leer(db, scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert (scan.risk_score, scan.grade, scan.commit_sha) == (95.0, "A", "c" * 40)
    assert len(hallazgos) == 1


@necesita_postgres
def test_guarda_la_evaluacion_de_la_ia(db, scan_id):
    from app.orchestrator.normalize import fingerprint
    from app.orchestrator.triage import TriageResult
    from app.worker.sql_store import SqlScanStore

    evaluado, sin_evaluar = _finding(2), _finding(3)
    resultado = _resultado(evaluado, sin_evaluar)
    resultado.triage = {
        fingerprint(evaluado): TriageResult(True, Severity.LOW, "Es un test\x00", "Nada que hacer"),
    }

    SqlScanStore(db).save_result(scan_id, "a" * 40, resultado)

    _, [con_ia, sin_ia] = _leer(db, scan_id)
    assert (con_ia.ai_is_false_positive, con_ia.ai_adjusted_severity) == (True, Severity.LOW)
    assert (con_ia.ai_explanation, con_ia.ai_remediation) == ("Es un test", "Nada que hacer")
    assert (sin_ia.ai_is_false_positive, sin_ia.ai_adjusted_severity, sin_ia.ai_explanation) == (None, None, None)
