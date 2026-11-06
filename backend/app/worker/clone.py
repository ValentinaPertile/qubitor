"""Clonado superficial de un repo público (etapa 1 del pipeline).

Versión mínima para cerrar el pipeline; el Módulo E la reemplaza por la
integración con OAuth y repos privados. El repo es código ajeno que no es de
confianza: solo se aceptan URLs de GitHub, no se crean enlaces simbólicos y
se corta el clonado si supera el límite.
"""

import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

MAX_REPO_BYTES = 50 * 1024 * 1024
CLONE_TIMEOUT_SECONDS = 120
_POLL_SECONDS = 0.5

_GITHUB_URL = re.compile(r"^https://github\.com/(?!\.)[\w.-]+/(?!\.)[\w.-]+?(\.git)?/?$")


class CloneError(Exception):
    """Falla transitoria del clonado: se puede reintentar."""


class CloneRejected(CloneError):
    """El repo no se va a poder clonar nunca: no tiene sentido reintentar."""


def clone_repository(url: str, destination: str) -> str:
    """Clona el último commit de `url` en `destination` y devuelve su SHA."""
    if not _GITHUB_URL.match(url):
        raise CloneRejected("Solo se pueden escanear URLs públicas de GitHub")
    _run_clone(_clone_command(url, destination), destination)
    return subprocess.run(
        ["git", "-C", destination, "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout.strip()


def remove_tree(path: str) -> None:
    """Borra el clon. Qubitor no conserva el código de los usuarios."""
    for root, _, files in os.walk(path):
        for name in files:
            file_path = os.path.join(root, name)
            if not os.path.islink(file_path):
                # En Windows Git deja archivos de solo lectura en .git.
                os.chmod(file_path, stat.S_IWRITE)
    shutil.rmtree(path, ignore_errors=True)


def _clone_command(url: str, destination: str) -> list[str]:
    return [
        "git",
        "-c", "core.symlinks=false",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
        "--", url, destination,
    ]


def _run_clone(command: list[str], destination: str) -> None:
    """Ejecuta el clonado midiendo cuánto ocupa, para cortarlo si se pasa."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + CLONE_TIMEOUT_SECONDS
    try:
        while process.poll() is None:
            if time.monotonic() > deadline:
                raise CloneError(f"El clonado superó el límite de {CLONE_TIMEOUT_SECONDS} s")
            if _size_of(destination) > MAX_REPO_BYTES:
                raise CloneRejected("El repo supera el límite de 50 MB")
            time.sleep(_POLL_SECONDS)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    stderr = process.stderr.read() if process.stderr else ""
    if process.returncode != 0:
        if "not found" in stderr.lower() or "could not read username" in stderr.lower():
            raise CloneRejected("El repo no existe o no es público")
        raise CloneError(f"git clone terminó con código {process.returncode}")
    if _size_of(destination) > MAX_REPO_BYTES:
        raise CloneRejected("El repo supera el límite de 50 MB")


def _size_of(path: str) -> int:
    total = 0
    for file in Path(path).rglob("*"):
        try:
            if file.is_file() and not file.is_symlink():
                total += file.stat().st_size
        except OSError:
            continue  # Git está creando y borrando archivos mientras se mide
    return total
