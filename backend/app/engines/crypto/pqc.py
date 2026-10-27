"""Criptografía post-cuántica (Módulo D).

Detecta algoritmos vulnerables a una computadora cuántica: RSA, ECDSA, ECDH y
DH (algoritmo de Shor) y AES-128 (algoritmo de Grover). Todo uso de
criptografía, aunque sea seguro, se registra con severidad `info` para armar
el inventario criptográfico (CBOM).

Las reglas llevan el prefijo `crypto.pqc.*`. CryptoEngine (compartido con el
Módulo C) llama a `scan_pqc` y junta sus resultados con los de `classic.py`.
"""

import ast
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from app.engines.base import Finding, Severity

# Carpetas que no son código del usuario: dependencias, entornos y builds.
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    algorithm: str
    title: str
    severity: Severity
    description: str


_SHOR_DESCRIPTION = (
    "{algorithm} es vulnerable al algoritmo de Shor: una computadora cuántica "
    "suficientemente grande podría romperlo. Los datos cifrados hoy pueden "
    "guardarse y descifrarse en el futuro (riesgo «cosechar ahora, descifrar "
    "después»). Planificar la migración a ML-KEM (FIPS 203) para intercambio "
    "de claves y a ML-DSA (FIPS 204) para firmas."
)

def _shor_rule(rule_id: str, algorithm: str, title: str) -> _Rule:
    return _Rule(
        rule_id=rule_id,
        algorithm=algorithm,
        title=title,
        severity=Severity.MEDIUM,
        description=_SHOR_DESCRIPTION.format(algorithm=algorithm),
    )


_ASYMMETRIC = "cryptography.hazmat.primitives.asymmetric"

# Reglas por llamada: nombre completo de la función → regla que dispara.
CALL_RULES = {
    f"{_ASYMMETRIC}.rsa.generate_private_key": _shor_rule(
        "crypto.pqc.rsa-keygen", "RSA",
        "Generación de clave RSA vulnerable a computación cuántica",
    ),
    f"{_ASYMMETRIC}.ec.generate_private_key": _shor_rule(
        "crypto.pqc.ec-keygen", "ECC",
        "Generación de clave de curva elíptica vulnerable a computación cuántica",
    ),
    f"{_ASYMMETRIC}.ec.ECDSA": _shor_rule(
        "crypto.pqc.ecdsa", "ECDSA",
        "Firma ECDSA vulnerable a computación cuántica",
    ),
    f"{_ASYMMETRIC}.ec.ECDH": _shor_rule(
        "crypto.pqc.ecdh", "ECDH",
        "Intercambio de claves ECDH vulnerable a computación cuántica",
    ),
}


def scan_pqc(repo_path: str) -> list[Finding]:
    repo = Path(repo_path)
    findings: list[Finding] = []
    for path in _iter_files(repo, ".py"):
        tree = _parse_python(path)
        if tree is None:
            continue
        findings.extend(_scan_python_tree(tree, path.relative_to(repo).as_posix()))
    return findings


def _iter_files(repo: Path, suffix: str) -> Iterator[Path]:
    for path in repo.rglob(f"*{suffix}"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(repo).parts):
            continue
        yield path


def _parse_python(path: Path) -> ast.Module | None:
    """Devuelve el AST del archivo, o None si no se puede leer o parsear.

    El contrato pide no lanzar excepciones por archivos ilegibles: se saltean.
    """
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
        return None


def _scan_python_tree(tree: ast.Module, file_path: str) -> list[Finding]:
    aliases = _collect_imports(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        rule = CALL_RULES.get(_qualified_name(node.func, aliases))
        if rule is not None:
            findings.append(_make_finding(rule, node, file_path))
    return findings


def _collect_imports(tree: ast.Module) -> dict[str, str]:
    """Mapea cada nombre importado al módulo real del que viene.

    `from cryptography.hazmat.primitives.asymmetric import rsa`
    → {"rsa": "cryptography.hazmat.primitives.asymmetric.rsa"}
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _qualified_name(func: ast.expr, aliases: dict[str, str]) -> str | None:
    """Arma el nombre completo de la función llamada, resolviendo los imports.

    `rsa.generate_private_key` → "cryptography...rsa.generate_private_key".
    Devuelve None si el nombre no viene de un import (por ejemplo, una
    variable propia del usuario que casualmente se llama `rsa`).
    """
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if not isinstance(func, ast.Name):
        return None
    base = aliases.get(func.id)
    if base is None:
        return None
    return ".".join([base, *reversed(parts)])


def _make_finding(rule: _Rule, node: ast.Call, file_path: str) -> Finding:
    return Finding(
        engine="crypto",
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        file_path=file_path,
        line=node.lineno,
        snippet=ast.unparse(node),
        description=rule.description,
        cwe="CWE-327",
        metadata={"algorithm": rule.algorithm},
    )
