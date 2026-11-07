import type { FindingRecord, Severity } from '@/types/Finding'
import type { Grade } from '@/types/Scan'

/** Pesos de severidad para el Risk Score (sección 3 del plan). */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 0.5,
  info: 0,
}

/** Corte inferior de cada nota (sección 5 del plan). */
export const GRADE_THRESHOLDS: readonly { grade: Grade; min: number }[] = [
  { grade: 'A', min: 90 },
  { grade: 'B', min: 75 },
  { grade: 'C', min: 60 },
  { grade: 'D', min: 40 },
  { grade: 'F', min: 0 },
]

/** Severidad que cuenta: la ajustada por la IA si hubo triage. */
export function effectiveSeverity(finding: FindingRecord): Severity {
  return finding.triage?.adjusted_severity ?? finding.severity
}

/**
 * Los hallazgos info son inventario o buenas prácticas sin riesgo (ej. CBOM):
 * no son vulnerabilidades, así que no tienen estado que gestionar ni penalizan.
 */
export function isInformational(finding: FindingRecord): boolean {
  return effectiveSeverity(finding) === 'info'
}

/** Solo penalizan los hallazgos abiertos, que no son falsos positivos ni info. */
export function countsTowardScore(finding: FindingRecord): boolean {
  return finding.status === 'open' && !finding.triage?.is_false_positive && !isInformational(finding)
}

export function penaltyOf(findings: readonly FindingRecord[]): number {
  return findings
    .filter(countsTowardScore)
    .reduce((total, f) => total + SEVERITY_WEIGHT[effectiveSeverity(f)], 0)
}

/** risk_score = max(0, 100 - penalización) */
export function riskScore(findings: readonly FindingRecord[]): number {
  return Math.max(0, 100 - penaltyOf(findings))
}

export function gradeFor(score: number): Grade {
  return GRADE_THRESHOLDS.find((t) => score >= t.min)?.grade ?? 'F'
}
