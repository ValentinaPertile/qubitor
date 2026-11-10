"""Cliente de OSV (https://osv.dev), la base pública y gratuita de vulnerabilidades.

Se usa `urllib` de la librería estándar para no sumar dependencias al scan-worker.
"""

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.error import URLError
from urllib.parse import quote

from app.engines.sca.manifests import Dependency

OSV_API = "https://api.osv.dev/v1"
# Sin User-Agent, urllib manda `Python-urllib/3.x`, que Cloudflare puede bloquear (error 1010).
USER_AGENT = "Qubitor"
BATCH_SIZE = 1000   # máximo de consultas por pedido que acepta querybatch
# Detalles de vulnerabilidades que se piden a OSV al mismo tiempo.
MAX_PARALLEL_REQUESTS = 8


class OsvError(Exception):
    """OSV no respondió o respondió algo inesperado."""


class OsvClient:
    def __init__(self, timeout: float = 15):
        self.timeout = timeout

    def query_batch(self, dependencies: list[Dependency]) -> list[list[str]]:
        """Devuelve, para cada dependencia y en el mismo orden, los IDs de sus vulnerabilidades."""
        results: list[list[str]] = []
        for start in range(0, len(dependencies), BATCH_SIZE):
            chunk = dependencies[start:start + BATCH_SIZE]
            body = {"queries": [
                {"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version}
                for dep in chunk
            ]}
            response = self._request("POST", f"{OSV_API}/querybatch", body)
            batch = response.get("results")
            if not isinstance(batch, list) or len(batch) != len(chunk):
                raise OsvError("OSV devolvió una cantidad de resultados distinta a la pedida")
            for result in batch:
                vulns = result.get("vulns", []) if isinstance(result, dict) else []
                results.append([vuln["id"] for vuln in vulns if "id" in vuln])
        return results

    def get_vuln(self, vuln_id: str) -> dict:
        """Detalle de una vulnerabilidad: alias (CVE), gravedad y versiones corregidas."""
        return self._request("GET", f"{OSV_API}/vulns/{quote(vuln_id)}")

    def get_vulns(self, vuln_ids: list[str]) -> dict[str, dict]:
        """Detalle de varias vulnerabilidades, pedidas en paralelo: id → detalle."""
        if not vuln_ids:
            return {}
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_REQUESTS) as pool:
            return dict(zip(vuln_ids, pool.map(self.get_vuln, vuln_ids), strict=True))

    def _request(self, method: str, url: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            url, data=data, method=method, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except (URLError, TimeoutError, ValueError) as error:
            raise OsvError(f"No se pudo consultar OSV: {error}") from error
        if not isinstance(payload, dict):
            raise OsvError("OSV devolvió una respuesta inesperada")
        return payload
