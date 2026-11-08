"""Pipeline de análisis de un repo ya clonado (Módulo A).

Une las etapas 2 a 5 del auditor: motores en paralelo, normalización, triage
con IA (Módulo E, ver triage.py) y Risk Score. El clonado y la persistencia los
coordina el scan-worker.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from app.engines.base import Engine, Finding
from app.orchestrator.normalize import deduplicate
from app.orchestrator.risk import grade, risk_score
from app.orchestrator.runner import run_engines
from app.orchestrator.triage import TriageProvider, TriageResult, run_triage


@dataclass
class ScanResult:
    findings: dict[str, Finding]  # fingerprint → hallazgo
    errors: dict[str, str]  # nombre del motor → error
    risk_score: float
    grade: str
    duration_seconds: float
    engine_count: int
    triage: dict[str, TriageResult] = field(default_factory=dict)  # fingerprint → evaluación de la IA

    @property
    def failed(self) -> bool:
        """True si fallaron todos los motores: no hay nada que mostrar."""
        return self.engine_count > 0 and len(self.errors) == self.engine_count


def analyze_repository(
    repo_path: str,
    engines: list[Engine],
    on_stage: Callable[[str], None] | None = None,
    triage: TriageProvider | None = None,
) -> ScanResult:
    """Corre los motores, normaliza, pide el triage y calcula el score.

    `on_stage` recibe cada etapa al empezar. `triage` es la función del Módulo E;
    sin ella, el score usa la severidad original.
    """
    report = on_stage or (lambda stage: None)
    start = time.monotonic()
    report("engines")
    engines_result = run_engines(engines, repo_path)
    report("normalize")
    findings = deduplicate(engines_result.findings)
    evaluations: dict[str, TriageResult] = {}
    if triage is not None:
        report("triage")
        evaluations = run_triage(findings, triage)
    report("score")
    # Todos los hallazgos están abiertos: cuentan salvo que la IA los marque como
    # falso positivo, con la severidad que ella ajustó (igual que la API y el frontend).
    score = risk_score(
        evaluations[fp].adjusted_severity if fp in evaluations else finding.severity
        for fp, finding in findings.items()
        if not (fp in evaluations and evaluations[fp].is_false_positive)
    )
    return ScanResult(
        findings=findings,
        errors=engines_result.errors,
        risk_score=score,
        grade=grade(score),
        duration_seconds=round(time.monotonic() - start, 2),
        engine_count=len(engines),
        triage=evaluations,
    )
