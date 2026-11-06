import ast
import re
from pathlib import Path
from typing import Iterator

from app.engines.base import Finding, Severity

# Extensiones a analizar
PYTHON_SUFFIXES = (".py",)
JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx")
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

def _create_finding(rule: str, title: str, severity: Severity, file_path: str, line: int, snippet: str, desc: str) -> Finding:
    return Finding(
        engine="crypto",
        rule_id=f"crypto.classic.{rule}",
        title=title,
        severity=severity,
        file_path=file_path,
        line=line,
        snippet=snippet.strip()[:200].replace("'", "***").replace('"', "***"), # Enmascaramiento rápido
        description=desc,
        cwe="CWE-327",
    )

def scan_classic(repo_path: str) -> list[Finding]:
    repo = Path(repo_path).resolve()
    findings = []
    
    for path in repo.rglob("*"):
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(repo):
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(repo).parts):
            continue
            
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
            
        rel_path = path.relative_to(repo).as_posix()
        
        if path.suffix in PYTHON_SUFFIXES:
            findings.extend(_scan_python(content, rel_path))
        elif path.suffix in JS_SUFFIXES:
            findings.extend(_scan_js(content, rel_path))
            
    return findings

def _scan_python(content: str, file_path: str) -> list[Finding]:
    findings = []
    try:
        tree = ast.parse(content, filename=file_path)
    except (SyntaxError, ValueError):
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _get_func_name(node.func)
            
            # MD5 / SHA1
            if func_name in ("hashlib.md5", "hashlib.sha1", "MD5", "SHA1"):
                findings.append(_create_finding("weak-hash", "Uso de algoritmo de hash roto (MD5/SHA-1)", Severity.HIGH, file_path, node.lineno, ast.unparse(node), "Colisiones prácticas. Usar SHA-256 para integridad y Argon2 o bcrypt para contraseñas."))
            
            # DES / 3DES / RC4 / Blowfish
            elif func_name in ("DES.new", "ARC4.new", "Blowfish.new", "TripleDES"):
                findings.append(_create_finding("weak-cipher", "Uso de cifrado obsoleto (DES/RC4/Blowfish)", Severity.HIGH, file_path, node.lineno, ast.unparse(node), "Rotos o deprecados. Migrar a AES-256-GCM."))
            
            # RSA < 2048 (Crucial para no pisarse con Valen)
            elif func_name in ("rsa.generate_private_key", "RSA.generate"):
                size = _get_kwarg(node, "key_size") or _get_arg(node, 1) if func_name == "rsa.generate_private_key" else _get_arg(node, 0)
                if isinstance(size, int) and size < 2048:
                    findings.append(_create_finding("rsa-weak-key", "Clave RSA menor a 2048 bits", Severity.HIGH, file_path, node.lineno, ast.unparse(node), "Factorizable con recursos clásicos. Mínimo 3072 bits."))
            
            # AES ECB
            elif func_name == "AES.new":
                mode = _get_arg(node, 1) or _get_kwarg(node, "mode")
                if mode == "AES.MODE_ECB" or mode == "MODE_ECB":
                    findings.append(_create_finding("aes-ecb", "AES en modo ECB", Severity.MEDIUM, file_path, node.lineno, ast.unparse(node), "El modo ECB filtra patrones del texto plano. Usar GCM o CBC con HMAC."))
            
            # TLS Inseguro (verify=False)
            elif func_name in ("requests.get", "requests.post", "requests.request"):
                verify = _get_kwarg(node, "verify")
                if verify is False:
                    findings.append(_create_finding("tls-insecure", "Validación de certificados TLS deshabilitada", Severity.HIGH, file_path, node.lineno, ast.unparse(node), "Protocolos inseguros o validación de certificados deshabilitada."))

        # Random no criptográfico
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "random" and node.attr in ("choice", "randint", "random", "choices"):
                findings.append(_create_finding("insecure-random", "Uso de random no criptográfico", Severity.MEDIUM, file_path, node.lineno, f"{node.value.id}.{node.attr}", "No es criptográficamente seguro. Usar el módulo `secrets`."))

    return findings

def _scan_js(content: str, file_path: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    
    for i, line in enumerate(lines, start=1):
        if re.search(r"createHash\(['\"](md5|sha1)['\"]\)", line, re.I):
            findings.append(_create_finding("weak-hash", "Uso de hash roto (MD5/SHA-1)", Severity.HIGH, file_path, i, line, "Usar SHA-256."))
        
        elif re.search(r"createCipheriv\(['\"](des|rc4|bf)", line, re.I):
            findings.append(_create_finding("weak-cipher", "Uso de cifrado obsoleto", Severity.HIGH, file_path, i, line, "Migrar a AES-256-GCM."))
            
        elif re.search(r"createCipheriv\(['\"]aes-\d{3}-ecb", line, re.I):
            findings.append(_create_finding("aes-ecb", "AES en modo ECB", Severity.MEDIUM, file_path, i, line, "El modo ECB es inseguro."))
            
        elif "Math.random()" in line:
            findings.append(_create_finding("insecure-random", "Math.random para tokens", Severity.MEDIUM, file_path, i, line, "No es criptográficamente seguro. Usar crypto.randomBytes."))
            
        elif "rejectUnauthorized: false" in line:
            findings.append(_create_finding("tls-insecure", "Validación TLS deshabilitada en Node", Severity.HIGH, file_path, i, line, "Peligro de Man-in-the-Middle."))
            
    return findings

# Funciones de ayuda para AST
def _get_func_name(node):
    if isinstance(node, ast.Attribute):
        return f"{_get_func_name(node.value)}.{node.attr}" if isinstance(node.value, ast.Name) else node.attr
    elif isinstance(node, ast.Name):
        return node.id
    return ""

def _get_kwarg(node, name):
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None

def _get_arg(node, index):
    if len(node.args) > index and isinstance(node.args[index], ast.Constant):
        return node.args[index].value
    elif len(node.args) > index and isinstance(node.args[index], ast.Attribute):
        return node.args[index].attr
    return None