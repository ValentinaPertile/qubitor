from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    respuesta = client.get("/health")
    assert respuesta.status_code == 200
    assert respuesta.json() == {"status": "ok"}


def test_cors_permite_el_frontend_local():
    respuesta = client.options(
        "/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert respuesta.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_rechaza_otros_origenes():
    respuesta = client.options(
        "/health",
        headers={"Origin": "https://malicioso.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in respuesta.headers
