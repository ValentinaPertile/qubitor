"""Configuración por variables de entorno (Módulo A).

En Render las variables se cargan en el panel de cada servicio; en local salen
de `backend/.env`, que no se commitea (ver `.env.example`).
"""

import os

from dotenv import load_dotenv

load_dotenv()

DEFAULT_CORS_ORIGINS = "http://localhost:5173"


def redis_url() -> str:
    """URL de Redis. Falla al usarla si falta, en vez de apuntar a localhost."""
    url = os.getenv("REDIS_URL")
    if not url:
        raise RuntimeError("Falta la variable de entorno REDIS_URL")
    return url


def cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]
