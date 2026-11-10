"""Tests del cliente de OSV, sin internet: se reemplaza `_request` por respuestas armadas."""

from urllib.error import URLError

import pytest

from app.engines.sca import osv
from app.engines.sca.manifests import Dependency
from app.engines.sca.osv import OsvClient, OsvError

REQUESTS = Dependency("requests", "2.19.0", "PyPI", "requirements.txt", 1)
LODASH = Dependency("lodash", "4.17.4", "npm", "package.json", 4)


class OsvDePrueba(OsvClient):
    """Registra cada pedido y responde con lo que se le indique."""

    def __init__(self, respuestas):
        super().__init__()
        self.respuestas = list(respuestas)
        self.pedidos = []

    def _request(self, method, url, body=None):
        self.pedidos.append((method, url, body))
        return self.respuestas.pop(0)


def test_query_batch_arma_la_consulta_y_devuelve_los_ids_en_orden():
    cliente = OsvDePrueba([{"results": [
        {"vulns": [{"id": "GHSA-x84v-xcm2-53pg"}, {"id": "PYSEC-2018-28"}]},
        {},
    ]}])

    assert cliente.query_batch([REQUESTS, LODASH]) == [
        ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"],
        [],
    ]
    assert cliente.pedidos == [("POST", "https://api.osv.dev/v1/querybatch", {"queries": [
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"},
        {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.4"},
    ]})]


def test_query_batch_divide_en_lotes(monkeypatch):
    monkeypatch.setattr(osv, "BATCH_SIZE", 1)
    cliente = OsvDePrueba([{"results": [{}]}, {"results": [{}]}])

    assert cliente.query_batch([REQUESTS, LODASH]) == [[], []]
    assert len(cliente.pedidos) == 2


def test_query_batch_falla_si_osv_devuelve_otra_cantidad_de_resultados():
    cliente = OsvDePrueba([{"results": []}])
    with pytest.raises(OsvError):
        cliente.query_batch([REQUESTS])


def test_get_vuln_pide_el_detalle_por_id():
    cliente = OsvDePrueba([{"id": "GHSA-x84v-xcm2-53pg"}])

    assert cliente.get_vuln("GHSA-x84v-xcm2-53pg") == {"id": "GHSA-x84v-xcm2-53pg"}
    assert cliente.pedidos[0][:2] == ("GET", "https://api.osv.dev/v1/vulns/GHSA-x84v-xcm2-53pg")


class OsvPorId(OsvClient):
    """Responde el detalle según el id pedido, sin importar el orden en que lleguen los hilos."""

    def _request(self, method, url, body=None):
        return {"id": url.rsplit("/", 1)[1]}


def test_get_vulns_devuelve_cada_detalle_con_su_id():
    ids = [f"GHSA-{i}" for i in range(20)]

    assert OsvPorId().get_vulns(ids) == {i: {"id": i} for i in ids}


def test_get_vulns_sin_ids_no_consulta():
    assert OsvDePrueba([]).get_vulns([]) == {}


def test_sin_conexion_se_convierte_en_osv_error(monkeypatch):
    def sin_internet(*args, **kwargs):
        raise URLError("sin conexión")

    monkeypatch.setattr(osv.urllib.request, "urlopen", sin_internet)

    with pytest.raises(OsvError):
        OsvClient().get_vuln("GHSA-x84v-xcm2-53pg")


def test_se_identifica_con_user_agent_propio(monkeypatch):
    agentes = []

    def urlopen(request, timeout):
        agentes.append(request.get_header("User-agent"))
        raise URLError("cortado acá")

    monkeypatch.setattr(osv.urllib.request, "urlopen", urlopen)

    with pytest.raises(OsvError):
        OsvClient().get_vuln("GHSA-x84v-xcm2-53pg")
    assert agentes == ["Qubitor"]
