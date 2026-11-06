"""API de Qubitor (Módulo A)."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import cors_origins

app = FastAPI(title="Qubitor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health")
def health() -> dict[str, str]:
    """Lo consultan el keep-alive y Better Stack: no depende de Redis ni de la base."""
    return {"status": "ok"}
