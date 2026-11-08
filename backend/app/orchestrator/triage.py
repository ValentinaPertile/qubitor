"""Punto de conexión del triage con IA (etapa 4 del pipeline).

El triage lo implementa el Módulo E en `app/ai/triage.py` con esta función:

    def triage_findings(findings: dict[str, Finding]) -> dict[str, TriageResult]:
        '''Recibe los hallazgos por fingerprint y devuelve la evaluación de los
        que pudo evaluar, por el mismo fingerprint.'''

El orquestador la llama entre la normalización y el Risk Score. Mientras el
módulo no exista, o si falla (sin cuota, sin red), el escaneo sigue con la
severidad original: el plan pide ese fallback.
"""

import importlib
import importlib.util
import logging
from collections.abc import Callable
from dataclasses import dataclass

from app.engines.base import Finding, Severity

logger = logging.getLogger(__name__)

PROVIDER_MODULE = "app.ai.triage"


@dataclass(frozen=True)
class TriageResult:
    """Lo que devuelve Gemini por hallazgo (response_schema de la sección 5 del plan)."""

    is_false_positive: bool
    adjusted_severity: Severity
    explanation: str
    remediation: str


TriageProvider = Callable[[dict[str, Finding]], dict[str, TriageResult]]


def load_provider() -> TriageProvider | None:
    """La función del Módulo E, o None si todavía no está."""
    try:
        if importlib.util.find_spec(PROVIDER_MODULE) is None:
            return None
    except (ModuleNotFoundError, ValueError):
        return None
    try:
        return importlib.import_module(PROVIDER_MODULE).triage_findings
    except Exception:
        # El módulo existe pero no carga (por ejemplo, le falta una dependencia).
        logger.exception("No se pudo cargar el triage con IA")
        return None


def run_triage(findings: dict[str, Finding], provider: TriageProvider | None) -> dict[str, TriageResult]:
    """Evalúa los hallazgos con la IA. Nunca lanza: ante cualquier falla devuelve {}.

    Los hallazgos info (inventario criptográfico) no se envían: no son
    vulnerabilidades y gastarían cuota de la API.
    """
    if provider is None:
        return {}
    to_review = {fp: f for fp, f in findings.items() if f.severity != Severity.INFO}
    if not to_review:
        return {}
    try:
        results = provider(to_review)
    except Exception:
        logger.exception("El triage con IA falló: se usa la severidad original")
        return {}
    return {fp: result for fp, result in (results or {}).items() if fp in to_review and _is_valid(result)}


def _is_valid(result: object) -> bool:
    """Descarta respuestas mal formadas en vez de guardarlas."""
    return (
        isinstance(result, TriageResult)
        and isinstance(result.is_false_positive, bool)
        and isinstance(result.adjusted_severity, Severity)
        and isinstance(result.explanation, str)
        and isinstance(result.remediation, str)
    )
