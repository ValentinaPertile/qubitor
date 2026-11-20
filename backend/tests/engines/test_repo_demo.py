"""Escanea el repo de demo real (qubitor-demo-vulnerable) de punta a punta.

Clona el repo desde GitHub y la parte de SCA consulta OSV, así que necesita
internet: correr con QUBITOR_TESTS_RED=1.
"""

import os
import subprocess

import pytest

from app.engines.crypto import CryptoEngine
from app.engines.sca import ScaEngine

REPO_DEMO = "https://github.com/ValentinaPertile/qubitor-demo-vulnerable.git"

pytestmark = pytest.mark.skipif(os.environ.get("QUBITOR_TESTS_RED") != "1",
                                reason="usa internet; correr con QUBITOR_TESTS_RED=1")


@pytest.fixture(scope="module")
def repo_demo(tmp_path_factory):
    destino = tmp_path_factory.mktemp("demo") / "repo"
    subprocess.run(["git", "clone", "--depth", "1", "--quiet", REPO_DEMO, str(destino)],
                   check=True, timeout=60)
    return str(destino)


def test_detecta_la_criptografia_post_cuantica_plantada(repo_demo):
    hallazgos = {(h.rule_id, h.file_path, h.line, h.severity.value)
                 for h in CryptoEngine().scan(repo_demo)
                 # Solo el código: los certificados del demo tienen su propio test (test_certs.py).
                 if h.rule_id.startswith("crypto.pqc.") and h.file_path.startswith("app/")}

    assert hallazgos == {
        ("crypto.pqc.rsa-keygen", "app/keys.py", 10, "medium"),
        ("crypto.pqc.ecdh", "app/keys.py", 15, "medium"),
        ("crypto.pqc.aes-128", "app/keys.py", 20, "low"),
        ("crypto.pqc.inventory.hash", "app/keys.py", 25, "info"),
        ("crypto.pqc.ecdsa", "app/signing.js", 5, "medium"),
        # AES-ECB plantado por el Módulo C: sin tamaño de clave, solo va al inventario.
        ("crypto.pqc.inventory.aes", "app/crypto_utils.py", 14, "info"),
    }


def test_rsa_de_1024_se_reporta_una_sola_vez_como_clasica(repo_demo):
    """El RSA de 1024 bits del Módulo C sale como high (clásica), no también como medium (pqc)."""
    en_la_linea = {h.rule_id for h in CryptoEngine().scan(repo_demo)
                   if h.file_path == "app/crypto_utils.py" and h.line == 9}

    assert en_la_linea == {"crypto.classic.rsa-weak-key"}


def test_detecta_las_dependencias_vulnerables_plantadas(repo_demo):
    cves = {h.cve for h in ScaEngine().scan(repo_demo)}

    assert {"CVE-2018-18074", "CVE-2019-10744"} <= cves
