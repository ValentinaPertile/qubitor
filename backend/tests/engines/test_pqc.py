from app.engines.crypto.pqc import _iter_files, scan_pqc


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
