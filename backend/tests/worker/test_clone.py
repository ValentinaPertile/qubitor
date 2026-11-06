import os
import sys

import pytest

from app.worker import clone
from app.worker.clone import CloneError, CloneRejected, clone_repository, remove_tree


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:a/b.git",
        "http://github.com/a/b",
        "file:///etc/passwd",
        "ext::sh -c id",
        "--upload-pack=touch /tmp/x",
        "https://github.com.malicioso.example/a/b",
        "https://usuario:clave@github.com/a/b",
        "https://github.com/a",
        "https://github.com/a/b/../../c",
        "https://github.com/../b",
        "https://github.com/a/..",
        "https://github.com/a/b?x=1",
        "https://gitlab.com/a/b",
    ],
)
def test_rechaza_urls_que_no_son_de_github(url, tmp_path):
    with pytest.raises(CloneRejected):
        clone_repository(url, str(tmp_path / "repo"))


def test_comando_endurecido():
    comando = clone._clone_command("https://github.com/a/b", "dest")

    assert "core.symlinks=false" in comando
    assert "protocol.allow=never" in comando
    assert "--no-recurse-submodules" in comando
    # La URL va después de "--": nunca se interpreta como una opción de git.
    assert comando[-3:] == ["--", "https://github.com/a/b", "dest"]


def _proceso(codigo):
    return [sys.executable, "-c", codigo]


def test_corta_el_clonado_si_supera_el_limite(tmp_path, monkeypatch):
    monkeypatch.setattr(clone, "MAX_REPO_BYTES", 1000)
    monkeypatch.setattr(clone, "_POLL_SECONDS", 0.01)
    destino = tmp_path / "repo"
    destino.mkdir()
    (destino / "grande.bin").write_bytes(b"x" * 2000)

    with pytest.raises(CloneRejected, match="50 MB"):
        clone._run_clone(_proceso("import time; time.sleep(30)"), str(destino))


def test_corta_el_clonado_si_tarda_demasiado(tmp_path, monkeypatch):
    monkeypatch.setattr(clone, "CLONE_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(clone, "_POLL_SECONDS", 0.01)

    with pytest.raises(CloneError, match="límite"):
        clone._run_clone(_proceso("import time; time.sleep(30)"), str(tmp_path))


def test_repo_inexistente_no_se_reintenta(tmp_path):
    codigo = "import sys; sys.stderr.write('remote: Repository not found.'); sys.exit(128)"
    with pytest.raises(CloneRejected, match="no existe"):
        clone._run_clone(_proceso(codigo), str(tmp_path))


def test_falla_de_red_se_puede_reintentar(tmp_path):
    codigo = "import sys; sys.stderr.write('Could not resolve host'); sys.exit(128)"
    with pytest.raises(CloneError) as error:
        clone._run_clone(_proceso(codigo), str(tmp_path))
    assert not isinstance(error.value, CloneRejected)


def test_remove_tree_borra_archivos_de_solo_lectura(tmp_path):
    carpeta = tmp_path / "repo" / ".git"
    carpeta.mkdir(parents=True)
    archivo = carpeta / "objeto"
    archivo.write_text("x")
    os.chmod(archivo, 0o444)

    remove_tree(str(tmp_path / "repo"))

    assert not (tmp_path / "repo").exists()


@pytest.mark.skipif(not os.getenv("QUBITOR_TESTS_RED"), reason="usa internet (QUBITOR_TESTS_RED=1)")
def test_clona_un_repo_real(tmp_path):
    destino = tmp_path / "repo"

    sha = clone_repository("https://github.com/octocat/Hello-World", str(destino))

    assert len(sha) == 40
    assert (destino / "README").exists()
