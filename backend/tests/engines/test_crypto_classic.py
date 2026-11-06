import pytest
from app.engines.base import Severity
from app.engines.crypto.classic import scan_classic

def _escribir(repo, ruta, contenido):
    archivo = repo / ruta
    archivo.parent.mkdir(parents=True, exist_ok=True)
    archivo.write_text(contenido, encoding="utf-8")

def test_python_detecta_rsa_menor_a_2048(tmp_path):
    codigo = """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
"""
    _escribir(tmp_path, "app.py", codigo)
    
    hallazgos = scan_classic(str(tmp_path))
    
    assert len(hallazgos) == 1
    assert hallazgos[0].rule_id == "crypto.classic.rsa-weak-key"
    assert hallazgos[0].severity == Severity.HIGH

def test_python_detecta_aes_ecb_y_md5(tmp_path):
    codigo = """
from Crypto.Cipher import AES
import hashlib
cipher = AES.new(b'clave', AES.MODE_ECB)
h = hashlib.md5(b'datos')
"""
    _escribir(tmp_path, "utils.py", codigo)
    
    hallazgos = scan_classic(str(tmp_path))
    reglas = [h.rule_id for h in hallazgos]
    
    assert "crypto.classic.aes-ecb" in reglas
    assert "crypto.classic.weak-hash" in reglas

def test_javascript_detecta_rc4_y_random_inseguro(tmp_path):
    codigo = """
const crypto = require('crypto');
const cipher = crypto.createCipheriv('rc4', key, iv);
const token = Math.random().toString();
"""
    _escribir(tmp_path, "auth.js", codigo)
    
    hallazgos = scan_classic(str(tmp_path))
    reglas = [h.rule_id for h in hallazgos]
    
    assert "crypto.classic.weak-cipher" in reglas
    assert "crypto.classic.insecure-random" in reglas

def test_ignora_archivos_fuera_del_repo(tmp_path):
    _escribir(tmp_path, ".venv/script.py", "hashlib.md5(b'123')")
    
    hallazgos = scan_classic(str(tmp_path))
    
    assert len(hallazgos) == 0