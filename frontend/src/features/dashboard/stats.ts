import { MODULE_VIEWS, viewOf, type ModuleView } from '@/lib/labels'
import { countsTowardScore, effectiveSeverity, gradeFor, isInformational, penaltyOf, riskScore } from '@/lib/risk'
import { ENGINES, SEVERITIES, type EngineName, type FindingRecord, type Severity } from '@/types/Finding'
import type { Grade } from '@/types/Scan'

export interface DashboardStats {
  score: number
  grade: Grade
  penalty: number
  /** Hallazgos que penalizan (abiertos, no falsos positivos y no info). */
  counted: number
  bySeverity: Record<Severity, number>
  byEngine: Record<EngineName, Record<Severity, number>>
  byView: Record<ModuleView, Record<Severity, number>>
}

const emptyRow = (): Record<Severity, number> =>
  Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>

/**
 * Métricas del dashboard calculadas en el cliente con la fórmula del plan, así
 * la nota se actualiza al instante cuando se marca un hallazgo.
 */
export function computeStats(findings: readonly FindingRecord[]): DashboardStats {
  const bySeverity = emptyRow()
  const byEngine = Object.fromEntries(ENGINES.map((e) => [e, emptyRow()])) as DashboardStats['byEngine']
  const byView = Object.fromEntries(MODULE_VIEWS.map((v) => [v.id, emptyRow()])) as DashboardStats['byView']

  let counted = 0
  for (const finding of findings) {
    // Los info se muestran como inventario (peso 0) pero no cuentan como
    // abiertos ni penalizan. Su estado no aplica, así que no se mira.
    if (isInformational(finding)) {
      if (!finding.triage?.is_false_positive) {
        bySeverity.info += 1
        byEngine[finding.engine].info += 1
      }
      continue
    }
    if (!countsTowardScore(finding)) continue
    const severity = effectiveSeverity(finding)
    counted += 1
    bySeverity[severity] += 1
    byEngine[finding.engine][severity] += 1
    byView[viewOf(finding)][severity] += 1
  }

  const score = riskScore(findings)
  return { score, grade: gradeFor(score), penalty: penaltyOf(findings), counted, bySeverity, byEngine, byView }
}
