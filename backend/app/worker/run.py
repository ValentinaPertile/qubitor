"""Punto de entrada del scan-worker: `python -m app.worker.run`."""

import logging
import os

from rq import SimpleWorker, Worker
from rq.serializers import JSONSerializer
from rq.timeouts import TimerDeathPenalty

from app.worker.queue import QUEUE_NAME, get_connection


class _NoForkWorker(SimpleWorker):
    """Windows no tiene fork ni SIGALRM: es solo para probar en local."""

    death_penalty_class = TimerDeathPenalty


def worker_class() -> type[Worker]:
    return Worker if hasattr(os, "fork") else _NoForkWorker


def main(burst: bool = False) -> None:
    logging.basicConfig(level=logging.INFO)
    worker = worker_class()([QUEUE_NAME], connection=get_connection(), serializer=JSONSerializer)
    worker.work(burst=burst, with_scheduler=False)


if __name__ == "__main__":
    main()
