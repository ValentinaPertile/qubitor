from app.engines.base import Severity
from app.engines.crypto.pqc import _iter_files, scan_pqc


def _escanear(tmp_path, codigo):
    (tmp_path / "app.py").write_text(codigo)
    return scan_pqc(str(tmp_path))


def test_repo_vacio_devuelve_lista_vacia(tmp_path):
    assert scan_pqc(str(tmp_path)) == []


def test_archivo_con_error_de_sintaxis_no_rompe(tmp_path):
    (tmp_path / "roto.py").write_text("def f(:\n")
    assert scan_pqc(str(tmp_path)) == []


def test_archivo_que_no_es_utf8_no_rompe(tmp_path):
    (tmp_path / "latin1.py").write_bytes("x = 'año'".encode("latin-1"))
    assert scan_pqc(str(tmp_path)) == []


def test_ignora_carpetas_de_dependencias(tmp_path):
    (tmp_path / "app.py").write_text("")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.py").write_text("")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "site.py").write_text("")

    encontrados = [p.name for p in _iter_files(tmp_path, ".py")]

    assert encontrados == ["app.py"]


# --- RSA ---

def test_detecta_generacion_de_clave_rsa(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "\n"
        "clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    ))

    assert len(hallazgos) == 1
    h = hallazgos[0]
    assert h.rule_id == "crypto.pqc.rsa-keygen"
    assert h.severity == Severity.MEDIUM
    assert h.file_path == "app.py"
    assert h.line == 3
    assert "generate_private_key" in h.snippet


def test_detecta_rsa_importando_la_funcion_directamente(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key\n"
        "clave = generate_private_key(65537, 3072)\n"
    ))
    assert [h.rule_id for h in hallazgos] == ["crypto.pqc.rsa-keygen"]


def test_detecta_rsa_con_alias(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "import cryptography.hazmat.primitives.asymmetric.rsa as r\n"
        "clave = r.generate_private_key(65537, 2048)\n"
    ))
    assert [h.rule_id for h in hallazgos] == ["crypto.pqc.rsa-keygen"]


def test_no_detecta_rsa_en_comentarios_ni_textos(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "# rsa.generate_private_key(65537, 2048)\n"
        "ayuda = 'usar rsa.generate_private_key para crear claves'\n"
    ))
    assert hallazgos == []


def test_no_detecta_objeto_propio_llamado_rsa(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "from mi_app import servicio as rsa\n"
        "rsa.generate_private_key()\n"
    ))
    assert hallazgos == []


# --- Curvas elípticas (ECDSA / ECDH) ---

def test_detecta_generacion_de_clave_de_curva_eliptica(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "clave = ec.generate_private_key(ec.SECP256R1())\n"
    ))

    assert len(hallazgos) == 1
    assert hallazgos[0].rule_id == "crypto.pqc.ec-keygen"
    assert hallazgos[0].severity == Severity.MEDIUM
    assert hallazgos[0].metadata["algorithm"] == "ECC"


def test_detecta_firma_ecdsa(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "from cryptography.hazmat.primitives import hashes\n"
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def firmar(clave, datos):\n"
        "    return clave.sign(datos, ec.ECDSA(hashes.SHA256()))\n"
    ))

    assert [h.rule_id for h in hallazgos] == ["crypto.pqc.ecdsa"]
    assert hallazgos[0].line == 4


def test_detecta_intercambio_ecdh(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def acordar(clave, clave_del_otro):\n"
        "    return clave.exchange(ec.ECDH(), clave_del_otro)\n"
    ))

    assert [h.rule_id for h in hallazgos] == ["crypto.pqc.ecdh"]


def test_nombrar_una_curva_sin_usarla_no_es_hallazgo(tmp_path):
    hallazgos = _escanear(tmp_path, (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "CURVA = ec.SECP256R1()\n"
    ))
    assert hallazgos == []
