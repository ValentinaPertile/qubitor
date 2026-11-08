import pytest

from app.engines.base import Engine, Finding, Severity
from app.orchestrator import triage as triage_module
from app.orchestrator.normalize import fingerprint
from app.orchestrator.pipeline import analyze_repository
from app.orchestrator.triage import TriageResult, load_provider, run_triage


def _finding(line, severity=Severity.HIGH):
    return Finding(
        engine="sast", rule_id="r", title="", severity=severity,
        file_path="a.py", line=line, snippet="", description="",
    )


class MotorFijo(Engine):
    name = "sast"

    def __init__(self, hallazgos):
        self.hallazgos = hallazgos

    def scan(self, repo_path):
        return self.hallazgos


ALTO, MEDIO, INFO = _finding(1), _finding(2, Severity.MEDIUM), _finding(3, Severity.INFO)


def _evaluacion(falso_positivo=False, severidad=Severity.LOW):
    return TriageResult(falso_positivo, severidad, "explicación", "remediación")


def test_sin_triage_el_score_usa_la_severidad_original(tmp_path):
    resultado = analyze_repository(str(tmp_path), [MotorFijo([ALTO, MEDIO, INFO])])

    assert resultado.risk_score == 100 - 5 - 2
    assert resultado.triage == {}


def test_el_score_usa_la_severidad_ajustada_y_saltea_falsos_positivos(tmp_path):
    def proveedor(hallazgos):
        return {
            fingerprint(ALTO): _evaluacion(falso_positivo=True),
            fingerprint(MEDIO): _evaluacion(severidad=Severity.CRITICAL),
        }

    resultado = analyze_repository(str(tmp_path), [MotorFijo([ALTO, MEDIO, INFO])], triage=proveedor)

    assert resultado.risk_score == 100 - 10  # el alto es falso positivo; el medio pasó a crítico
    assert set(resultado.triage) == {fingerprint(ALTO), fingerprint(MEDIO)}


def test_avisa_la_etapa_de_triage_solo_si_hay_proveedor(tmp_path):
    con, sin = [], []
    analyze_repository(str(tmp_path), [], on_stage=con.append, triage=lambda h: {})
    analyze_repository(str(tmp_path), [], on_stage=sin.append)

    assert con == ["engines", "normalize", "triage", "score"]
    assert sin == ["engines", "normalize", "score"]


def test_no_manda_los_hallazgos_info_a_la_ia():
    recibidos = []
    run_triage({fingerprint(f): f for f in (ALTO, INFO)}, lambda h: recibidos.append(set(h)) or {})

    assert recibidos == [{fingerprint(ALTO)}]


def test_sin_hallazgos_para_revisar_no_llama_a_la_ia():
    llamadas = []
    assert run_triage({fingerprint(INFO): INFO}, lambda h: llamadas.append(h) or {}) == {}
    assert llamadas == []


def test_si_la_ia_falla_se_sigue_con_la_severidad_original(tmp_path):
    def sin_cuota(hallazgos):
        raise RuntimeError("429: se agotó la cuota de Gemini")

    resultado = analyze_repository(str(tmp_path), [MotorFijo([ALTO])], triage=sin_cuota)

    assert resultado.triage == {}
    assert resultado.risk_score == 95


def test_descarta_respuestas_mal_formadas():
    hallazgos = {fingerprint(ALTO): ALTO, fingerprint(MEDIO): MEDIO}

    def proveedor(h):
        return {
            fingerprint(ALTO): TriageResult(False, "critical", "x", "y"),  # severidad como texto
            fingerprint(MEDIO): {"is_false_positive": True},  # no es un TriageResult
            "fingerprint-inventado": _evaluacion(),
        }

    assert run_triage(hallazgos, proveedor) == {}


def test_sin_el_modulo_de_ia_no_hay_proveedor(monkeypatch):
    monkeypatch.setattr(triage_module, "PROVIDER_MODULE", "app.ai_que_no_existe.triage")
    assert load_provider() is None


def test_carga_la_funcion_del_modulo_e(monkeypatch, tmp_path):
    (tmp_path / "ia_falsa").mkdir()
    (tmp_path / "ia_falsa" / "__init__.py").write_text("")
    (tmp_path / "ia_falsa" / "triage.py").write_text("def triage_findings(findings):\n    return {}\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(triage_module, "PROVIDER_MODULE", "ia_falsa.triage")

    proveedor = load_provider()

    assert proveedor is not None and proveedor.__name__ == "triage_findings"


def test_si_el_modulo_no_carga_no_rompe_el_escaneo(monkeypatch, tmp_path):
    (tmp_path / "ia_rota").mkdir()
    (tmp_path / "ia_rota" / "__init__.py").write_text("")
    (tmp_path / "ia_rota" / "triage.py").write_text("import libreria_que_no_esta_instalada\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(triage_module, "PROVIDER_MODULE", "ia_rota.triage")

    assert load_provider() is None


@pytest.mark.parametrize("respuesta", [None, {}])
def test_respuesta_vacia(respuesta):
    assert run_triage({fingerprint(ALTO): ALTO}, lambda h: respuesta) == {}
