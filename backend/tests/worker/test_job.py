import os
from pathlib import Path

import fakeredis
import pytest
from rq.job import JobStatus
from rq.registry import FailedJobRegistry
from rq.serializers import JSONSerializer

from app.engines.base import Engine, Finding, Severity
from app.worker import job as job_module
from app.worker.clone import CloneError, CloneRejected
from app.worker.queue import QUEUE_NAME, enqueue_scan, get_queue
from app.worker.run import _NoForkWorker

URL = "https://github.com/a/b"


class StoreDePrueba:
    def __init__(self):
        self.eventos = []

    def mark_running(self, scan_id):
        self.eventos.append(("running", scan_id))

    def save_result(self, scan_id, commit_sha, result):
        self.eventos.append(("saved", scan_id, commit_sha, len(result.findings)))

    def mark_failed(self, scan_id, error):
        self.eventos.append(("failed", scan_id, error))


class MotorFijo(Engine):
    name = "sast"

    def scan(self, repo_path):
        assert Path(repo_path, "app.py").exists()
        return [
            Finding(
                engine="sast", rule_id="r", title="", severity=Severity.HIGH,
                file_path="app.py", line=1, snippet="", description="",
            )
        ]


class MotorRoto(Engine):
    name = "roto"

    def scan(self, repo_path):
        raise RuntimeError("no anda")


@pytest.fixture
def store(monkeypatch):
    store = StoreDePrueba()
    monkeypatch.setattr(job_module, "get_store", lambda: store)
    return store


@pytest.fixture
def clones(monkeypatch, tmp_path):
    """Reemplaza git por un clon falso y guarda las carpetas usadas."""
    usadas = []

    def clon_falso(url, destino):
        os.makedirs(destino)
        Path(destino, "app.py").write_text("x = 1\n")
        usadas.append(destino)
        return "a" * 40

    monkeypatch.setattr(job_module, "clone_repository", clon_falso)
    monkeypatch.setenv("REPOS_DIR", str(tmp_path))
    return usadas


def test_escaneo_completo(store, clones, monkeypatch):
    monkeypatch.setattr(job_module, "default_engines", lambda: [MotorFijo()])

    resumen = job_module.run_scan("abc", URL)

    assert store.eventos == [("running", "abc"), ("saved", "abc", "a" * 40, 1)]
    assert resumen["status"] == "completed"
    assert resumen["findings"] == 1
    assert resumen["risk_score"] == 95
    assert resumen["grade"] == "A"


def test_siempre_borra_el_clon(store, clones, monkeypatch, tmp_path):
    monkeypatch.setattr(job_module, "default_engines", lambda: [MotorFijo()])
    job_module.run_scan("abc", URL)

    assert clones
    assert not os.path.exists(clones[0])
    assert list(tmp_path.iterdir()) == []


def test_borra_el_clon_si_explota_el_analisis(store, clones, monkeypatch, tmp_path):
    def explota(*args):
        raise ValueError("bug")

    monkeypatch.setattr(job_module, "analyze_repository", explota)
    monkeypatch.setattr(job_module, "default_engines", lambda: [])

    with pytest.raises(ValueError):
        job_module.run_scan("abc", URL)

    assert list(tmp_path.iterdir()) == []


def test_si_fallan_todos_los_motores_el_escaneo_falla(store, clones, monkeypatch):
    monkeypatch.setattr(job_module, "default_engines", lambda: [MotorRoto()])

    resumen = job_module.run_scan("abc", URL)

    assert resumen["status"] == "failed"
    assert store.eventos[-1] == ("failed", "abc", "Fallaron todos los motores")


def test_escaneo_parcial_si_falla_un_motor(store, clones, monkeypatch):
    monkeypatch.setattr(job_module, "default_engines", lambda: [MotorRoto(), MotorFijo()])

    resumen = job_module.run_scan("abc", URL)

    assert resumen["status"] == "completed"
    assert list(resumen["engine_errors"]) == ["roto"]


def test_motores_registrados():
    assert {motor.name for motor in job_module.default_engines()} == {"sast", "sca", "secrets"}


# Con la cola: se ejecuta con un worker real de RQ sobre Redis falso.


def _procesar(redis):
    worker = _NoForkWorker([QUEUE_NAME], connection=redis, serializer=JSONSerializer)
    worker.work(burst=True, with_scheduler=False)


@pytest.fixture
def redis():
    return fakeredis.FakeStrictRedis()


def test_el_worker_toma_el_trabajo_de_la_cola(store, clones, monkeypatch, redis):
    monkeypatch.setattr(job_module, "default_engines", lambda: [MotorFijo()])
    trabajo = enqueue_scan("abc", URL, connection=redis)

    _procesar(redis)

    trabajo.refresh()
    assert trabajo.get_status() == JobStatus.FINISHED
    assert trabajo.return_value()["grade"] == "A"


def test_repo_rechazado_no_se_reintenta(store, monkeypatch, redis):
    llamadas = []

    def rechaza(url, destino):
        llamadas.append(url)
        raise CloneRejected("El repo no existe o no es público")

    monkeypatch.setattr(job_module, "clone_repository", rechaza)
    enqueue_scan("abc", URL, connection=redis)

    _procesar(redis)

    assert len(llamadas) == 1
    assert store.eventos[-1] == ("failed", "abc", "El repo no existe o no es público")


def test_falla_transitoria_se_reintenta_y_termina_en_la_cola_de_errores(store, monkeypatch, redis):
    llamadas = []

    def falla(url, destino):
        llamadas.append(url)
        raise CloneError("sin red")

    monkeypatch.setattr(job_module, "clone_repository", falla)
    enqueue_scan("abc", URL, connection=redis)

    _procesar(redis)

    assert len(llamadas) == 3  # el intento original y 2 reintentos
    # Marca el escaneo como fallido una sola vez, en el último intento.
    assert [e for e in store.eventos if e[0] == "failed"] == [("failed", "abc", "CloneError: sin red")]
    registro = FailedJobRegistry(queue=get_queue(redis))
    assert registro.get_job_ids() == ["scan-abc"]
