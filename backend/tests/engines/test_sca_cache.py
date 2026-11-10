import io
import json

import pytest

from app.engines.sca import ScaEngine
from app.engines.sca.cache import (
    TTL_SECONDS,
    CachedOsvClient,
    KvCache,
    KvError,
    default_osv_client,
    query_key,
    vuln_key,
)
from app.engines.sca.manifests import Dependency
from app.engines.sca.osv import OsvClient

REQUESTS = Dependency("requests", "2.19.0", "PyPI", "requirements.txt", 1)
FLASK = Dependency("flask", "3.0.0", "PyPI", "requirements.txt", 2)
LODASH = Dependency("lodash", "4.17.4", "npm", "package.json", None)

GHSA = {"id": "GHSA-x84v-xcm2-53pg", "aliases": ["CVE-2018-18074"], "database_specific": {"severity": "HIGH"}}


class KvFalso:
    def __init__(self, falla=False):
        self.datos = {}
        self.falla = falla
        self.lecturas = 0
        self.escrituras = 0

    def get_many(self, keys):
        self.lecturas += 1
        if self.falla:
            raise KvError("sin red")
        return {k: self.datos[k] for k in keys if k in self.datos}

    def put_many(self, items, ttl=TTL_SECONDS):
        self.escrituras += 1
        if self.falla:
            raise KvError("sin red")
        self.datos.update(items)


class OsvFalso:
    def __init__(self, ids_por_paquete=None, detalles=None):
        self.ids_por_paquete = ids_por_paquete or {}
        self.detalles = detalles or {}
        self.consultados = []
        self.detalles_pedidos = []

    def query_batch(self, dependencias):
        self.consultados.extend(d.name for d in dependencias)
        return [self.ids_por_paquete.get(d.name, []) for d in dependencias]

    def get_vulns(self, vuln_ids):
        self.detalles_pedidos.extend(vuln_ids)
        return {i: self.detalles[i] for i in vuln_ids}


def _cliente(kv=None, osv=None):
    osv = osv or OsvFalso({"requests": [GHSA["id"]]}, {GHSA["id"]: GHSA})
    kv = kv or KvFalso()
    return CachedOsvClient(osv, kv), osv, kv


def test_la_primera_vez_consulta_osv_y_guarda_tambien_lo_que_no_tiene_fallas():
    cliente, osv, kv = _cliente()

    assert cliente.query_batch([REQUESTS, FLASK]) == [[GHSA["id"]], []]

    assert osv.consultados == ["requests", "flask"]
    assert json.loads(kv.datos[query_key(REQUESTS)]) == [GHSA["id"]]
    assert json.loads(kv.datos[query_key(FLASK)]) == []


def test_la_segunda_vez_sale_de_la_cache_sin_consultar_osv():
    cliente, osv, _ = _cliente()
    cliente.query_batch([REQUESTS, FLASK])
    osv.consultados.clear()

    assert cliente.query_batch([REQUESTS, FLASK]) == [[GHSA["id"]], []]
    assert osv.consultados == []


def test_solo_consulta_las_que_faltan_y_respeta_el_orden():
    cliente, osv, _ = _cliente()
    cliente.query_batch([FLASK])
    osv.consultados.clear()

    assert cliente.query_batch([REQUESTS, FLASK, LODASH]) == [[GHSA["id"]], [], []]
    assert osv.consultados == ["requests", "lodash"]


def test_otra_version_del_mismo_paquete_es_otra_clave():
    cliente, osv, _ = _cliente()
    cliente.query_batch([REQUESTS])
    osv.consultados.clear()

    cliente.query_batch([Dependency("requests", "2.32.0", "PyPI", "requirements.txt", 1)])

    assert osv.consultados == ["requests"]


def test_el_detalle_de_cada_vulnerabilidad_tambien_se_guarda():
    cliente, osv, kv = _cliente()

    assert cliente.get_vulns([GHSA["id"]]) == {GHSA["id"]: GHSA}
    assert cliente.get_vuln(GHSA["id"]) == GHSA

    assert osv.detalles_pedidos == [GHSA["id"]]
    assert json.loads(kv.datos[vuln_key(GHSA["id"])]) == GHSA


def test_un_valor_roto_en_la_cache_se_vuelve_a_pedir():
    cliente, osv, kv = _cliente()
    kv.datos[query_key(REQUESTS)] = "esto no es json"
    kv.datos[vuln_key(GHSA["id"])] = '{"sin": "id"}'

    assert cliente.query_batch([REQUESTS]) == [[GHSA["id"]]]
    assert cliente.get_vulns([GHSA["id"]]) == {GHSA["id"]: GHSA}
    assert osv.consultados == ["requests"]
    assert osv.detalles_pedidos == [GHSA["id"]]


def test_si_kv_falla_consulta_osv_directo_y_apaga_la_cache(caplog):
    cliente, osv, kv = _cliente(kv=KvFalso(falla=True))

    assert cliente.query_batch([REQUESTS]) == [[GHSA["id"]]]
    assert cliente.get_vulns([GHSA["id"]]) == {GHSA["id"]: GHSA}

    assert cliente.enabled is False
    # Después del primer error no vuelve a intentar con KV en ese escaneo.
    assert (kv.lecturas, kv.escrituras) == (1, 0)
    assert "Caché de OSV en KV desactivada" in caplog.text


def test_el_motor_con_cache_no_consulta_osv_en_el_segundo_escaneo(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\nflask==3.0.0\n")
    cliente, osv, _ = _cliente()
    motor = ScaEngine(cliente)

    primero = motor.scan(str(tmp_path))
    osv.consultados.clear()
    osv.detalles_pedidos.clear()
    segundo = motor.scan(str(tmp_path))

    assert [h.cve for h in primero] == [h.cve for h in segundo] == ["CVE-2018-18074"]
    assert osv.consultados == [] and osv.detalles_pedidos == []


def test_sin_variables_usa_osv_directo(monkeypatch):
    for variable in ("CF_ACCOUNT_ID", "R2_ACCOUNT_ID", "CF_KV_NAMESPACE_ID", "CF_API_TOKEN"):
        monkeypatch.delenv(variable, raising=False)

    assert type(default_osv_client()) is OsvClient


def test_con_las_variables_usa_la_cache(monkeypatch):
    monkeypatch.delenv("CF_ACCOUNT_ID", raising=False)
    monkeypatch.setenv("R2_ACCOUNT_ID", "cuenta123")
    monkeypatch.setenv("CF_KV_NAMESPACE_ID", "ns456")
    monkeypatch.setenv("CF_API_TOKEN", "token-falso")

    cliente = default_osv_client()

    assert isinstance(cliente, CachedOsvClient)
    assert cliente.cache.base.endswith("/accounts/cuenta123/storage/kv/namespaces/ns456")


# La parte HTTP de KvCache, con urlopen reemplazado.


class Respuesta(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture
def pedidos(monkeypatch):
    """Guarda cada pedido a la API de Cloudflare y responde como KV."""
    hechos = []

    def urlopen(request, timeout):
        cuerpo = json.loads(request.data)
        hechos.append((request.get_method(), request.full_url, request.get_header("Authorization"), cuerpo))
        if request.full_url.endswith("/bulk/get"):
            valores = {k: ("[]" if k.endswith("0") else None) for k in cuerpo["keys"]}
            return Respuesta(json.dumps({"success": True, "result": {"values": valores}}).encode())
        return Respuesta(json.dumps({"success": True, "result": {}}).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    return hechos


def test_kv_lee_de_a_cien_claves_y_omite_las_que_no_estan(pedidos):
    kv = KvCache("cuenta", "ns", "token-falso")

    encontrados = kv.get_many([f"clave{i}" for i in range(250)])

    assert [len(cuerpo["keys"]) for _, _, _, cuerpo in pedidos] == [100, 100, 50]
    assert all(metodo == "POST" and url.endswith("/namespaces/ns/bulk/get") for metodo, url, _, _ in pedidos)
    assert pedidos[0][2] == "Bearer token-falso"
    assert len(encontrados) == 25 and encontrados["clave10"] == "[]"


def test_kv_escribe_en_lote_con_vencimiento_de_24_horas(pedidos):
    KvCache("cuenta", "ns", "token-falso").put_many({"a": "1", "b": "2"})

    metodo, url, _, cuerpo = pedidos[0]
    assert (metodo, url.endswith("/namespaces/ns/bulk")) == ("PUT", True)
    assert cuerpo == [
        {"key": "a", "value": "1", "expiration_ttl": 86400},
        {"key": "b", "value": "2", "expiration_ttl": 86400},
    ]


def test_kv_con_error_de_la_api_lanza_kverror(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: Respuesta(b'{"success": false, "errors": [{"message": "Authentication error"}]}'),
    )

    with pytest.raises(KvError):
        KvCache("cuenta", "ns", "token-falso").get_many(["a"])


def test_kv_se_identifica_con_user_agent_propio(monkeypatch):
    agentes = []

    def urlopen(request, timeout):
        agentes.append(request.get_header("User-agent"))
        return Respuesta(json.dumps({"success": True, "result": {"values": {}}}).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)

    KvCache("cuenta", "ns", "token").get_many(["a"])
    assert agentes == ["Qubitor"]
