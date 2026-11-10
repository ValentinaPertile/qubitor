"""Caché de las respuestas de OSV en Cloudflare Workers KV (Módulo D).

Las vulnerabilidades de una versión de un paquete cambian poco de un día para
otro, así que se guardan 24 horas en KV, una base clave-valor NoSQL:

- `osv:q:<ecosistema>|<paquete>|<versión>` → ids de sus vulnerabilidades. Se
  guarda también la lista vacía: la mayoría de las dependencias no tiene
  fallas, y es lo que más consultas ahorra.
- `osv:v:<id>` → detalle de la vulnerabilidad.

Se usa la API REST de Cloudflare leyendo y escribiendo de a lotes, para hacer
pocos pedidos por escaneo. Si KV falla, la caché se apaga para ese escaneo y
se consulta OSV directo: el escaneo nunca falla por la caché.

Sin las variables `CF_*` no hay caché y se usa OSV directo.
"""

import json
import logging
import os
import urllib.request
from urllib.error import URLError

from app.engines.sca.manifests import Dependency
from app.engines.sca.osv import USER_AGENT, OsvClient

logger = logging.getLogger(__name__)

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
TTL_SECONDS = 24 * 60 * 60
READ_BATCH = 100  # máximo de claves por lectura que acepta KV
WRITE_BATCH = 1000


class KvError(Exception):
    """KV no respondió o respondió algo inesperado."""


class KvCache:
    """Cliente mínimo de la API REST de Workers KV: leer y escribir de a lotes."""

    def __init__(self, account_id: str, namespace_id: str, api_token: str, timeout: float = 5):
        self.base = f"{CLOUDFLARE_API}/accounts/{account_id}/storage/kv/namespaces/{namespace_id}"
        self.api_token = api_token
        self.timeout = timeout

    def get_many(self, keys: list[str]) -> dict[str, str]:
        """Valores guardados de esas claves; las que no están no aparecen."""
        found: dict[str, str] = {}
        for start in range(0, len(keys), READ_BATCH):
            chunk = keys[start:start + READ_BATCH]
            response = self._request("POST", f"{self.base}/bulk/get", {"keys": chunk, "type": "text"})
            values = (response.get("result") or {}).get("values")
            if not isinstance(values, dict):
                raise KvError("KV devolvió una respuesta inesperada")
            found.update({k: v for k, v in values.items() if isinstance(v, str)})
        return found

    def put_many(self, items: dict[str, str], ttl: int = TTL_SECONDS) -> None:
        pairs = [{"key": k, "value": v, "expiration_ttl": ttl} for k, v in items.items()]
        for start in range(0, len(pairs), WRITE_BATCH):
            self._request("PUT", f"{self.base}/bulk", pairs[start:start + WRITE_BATCH])

    def _request(self, method: str, url: str, body: object) -> dict:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            method=method,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_token}",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except (URLError, TimeoutError, ValueError) as error:
            raise KvError(f"No se pudo consultar KV: {error}") from error
        if not isinstance(payload, dict) or not payload.get("success"):
            raise KvError("KV respondió con un error")
        return payload


class CachedOsvClient:
    """Mismo uso que OsvClient, pero primero busca en KV y guarda lo que pide a OSV."""

    def __init__(self, client: OsvClient, cache: KvCache):
        self.client = client
        self.cache = cache
        self.enabled = True

    def query_batch(self, dependencies: list[Dependency]) -> list[list[str]]:
        keys = [query_key(dep) for dep in dependencies]
        cached = self._read(keys, _parse_ids)
        missing = [dep for dep, key in zip(dependencies, keys, strict=True) if key not in cached]
        if missing:
            fresh = self.client.query_batch(missing)
            new = {query_key(dep): ids for dep, ids in zip(missing, fresh, strict=True)}
            self._write({key: json.dumps(ids) for key, ids in new.items()})
            cached.update(new)
        return [cached[key] for key in keys]

    def get_vuln(self, vuln_id: str) -> dict:
        return self.get_vulns([vuln_id])[vuln_id]

    def get_vulns(self, vuln_ids: list[str]) -> dict[str, dict]:
        keys = {vuln_key(vuln_id): vuln_id for vuln_id in vuln_ids}
        cached = {keys[key]: vuln for key, vuln in self._read(list(keys), _parse_vuln).items()}
        missing = [vuln_id for vuln_id in vuln_ids if vuln_id not in cached]
        if missing:
            fresh = self.client.get_vulns(missing)
            self._write({vuln_key(vuln_id): json.dumps(vuln) for vuln_id, vuln in fresh.items()})
            cached.update(fresh)
        return {vuln_id: cached[vuln_id] for vuln_id in vuln_ids}

    def _read(self, keys: list[str], parse) -> dict:
        if not self.enabled or not keys:
            return {}
        try:
            raw = self.cache.get_many(keys)
        except KvError as error:
            self._disable(error)
            return {}
        parsed = {key: parse(value) for key, value in raw.items()}
        # Un valor roto en la caché cuenta como que no está: se vuelve a pedir a OSV.
        return {key: value for key, value in parsed.items() if value is not None}

    def _write(self, items: dict[str, str]) -> None:
        if not self.enabled or not items:
            return
        try:
            self.cache.put_many(items)
        except KvError as error:
            self._disable(error)

    def _disable(self, error: KvError) -> None:
        logger.warning("Caché de OSV en KV desactivada para este escaneo: %s", error)
        self.enabled = False


def query_key(dep: Dependency) -> str:
    return f"osv:q:{dep.ecosystem}|{dep.name}|{dep.version}"


def vuln_key(vuln_id: str) -> str:
    return f"osv:v:{vuln_id}"


def get_kv_cache() -> KvCache | None:
    """La caché configurada por variables de entorno, o None si falta alguna."""
    account_id = os.getenv("CF_ACCOUNT_ID") or os.getenv("R2_ACCOUNT_ID")
    namespace_id = os.getenv("CF_KV_NAMESPACE_ID")
    api_token = os.getenv("CF_API_TOKEN")
    if not (account_id and namespace_id and api_token):
        return None
    return KvCache(account_id, namespace_id, api_token)


def default_osv_client() -> OsvClient | CachedOsvClient:
    cache = get_kv_cache()
    return CachedOsvClient(OsvClient(), cache) if cache else OsvClient()


def _parse_ids(value: str) -> list[str] | None:
    try:
        ids = json.loads(value)
    except ValueError:
        return None
    return ids if isinstance(ids, list) and all(isinstance(i, str) for i in ids) else None


def _parse_vuln(value: str) -> dict | None:
    try:
        vuln = json.loads(value)
    except ValueError:
        return None
    return vuln if isinstance(vuln, dict) and "id" in vuln else None
