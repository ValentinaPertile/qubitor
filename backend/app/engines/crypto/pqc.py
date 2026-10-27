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
from pathlib import Path

from app.engines.base import Finding

# Carpetas que no son código del usuario: dependencias, entornos y builds.
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


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
    # Las reglas se agregan en los próximos pasos.
    return []
