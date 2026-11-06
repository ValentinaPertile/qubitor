"""Cola de escaneos sobre Redis con RQ (Módulo A).

La API publica un trabajo y responde al instante; el scan-worker lo toma en otro
servicio. Los trabajos que agotan sus reintentos quedan en la cola de errores
(`FailedJobRegistry` de RQ).
"""

from redis import Redis
from rq import Queue, Retry
from rq.job import Job
from rq.serializers import JSONSerializer

from app.config import redis_url

QUEUE_NAME = "scans"
SCAN_JOB = "app.worker.job.run_scan"

# Reintentos ante fallas transitorias. Sin intervalo: esperar requiere el
# scheduler de RQ, que consulta Redis todo el tiempo y gasta la cuota de Upstash.
MAX_RETRIES = 2

JOB_TIMEOUT_SECONDS = 300  # clonado + motores + triage
RESULT_TTL_SECONDS = 60 * 60
FAILURE_TTL_SECONDS = 7 * 24 * 60 * 60  # para poder revisar la cola de errores


def get_connection() -> Redis:
    return Redis.from_url(redis_url(), socket_connect_timeout=5, health_check_interval=30)


def get_queue(connection: Redis | None = None) -> Queue:
    # JSON en lugar de pickle: los datos de un trabajo nunca ejecutan código al leerse.
    return Queue(QUEUE_NAME, connection=connection or get_connection(), serializer=JSONSerializer)


def enqueue_scan(scan_id: str, repo_url: str, connection: Redis | None = None) -> Job:
    """Publica un escaneo. El id del trabajo evita encolar dos veces el mismo."""
    return get_queue(connection).enqueue_call(
        SCAN_JOB,
        args=(scan_id, repo_url),
        job_id=f"scan-{scan_id}",
        timeout=JOB_TIMEOUT_SECONDS,
        result_ttl=RESULT_TTL_SECONDS,
        failure_ttl=FAILURE_TTL_SECONDS,
        retry=Retry(max=MAX_RETRIES),
    )
