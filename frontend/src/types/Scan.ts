import type { EngineName } from './Finding'

/**
 * Tipos de repositorios y escaneos. Provisorios: siguen el diseño de API de
 * docs/ARCHITECTURE.md hasta que el Módulo A publique los modelos reales.
 */

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F'

/** Igual al enum ScanStatus del backend: queued → running → completed | failed. */
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'

/** Etapas del pipeline del auditor (sección 2 del plan). */
export type ScanStage = 'clone' | 'engines' | 'normalize' | 'triage' | 'score' | 'persist'

export const SCAN_STAGES: readonly ScanStage[] = [
  'clone',
  'engines',
  'normalize',
  'triage',
  'score',
  'persist',
]

export interface Repository {
  id: string
  provider: 'github' | 'gitlab'
  /** ej. "qubitor-org/qubitor-demo-vulnerable" */
  full_name: string
  url: string
  default_branch: string
  connected_at: string
}

export interface Scan {
  id: string
  repository_id: string
  status: ScanStatus
  engines: EngineName[]
  /** 0 a 100; null mientras está en cola */
  progress: number | null
  stage: ScanStage | null
  commit_sha: string | null
  started_at: string
  finished_at: string | null
  risk_score: number | null
  grade: Grade | null
  error: string | null
}

/** GET /scans/{id}/report: URLs firmadas de R2 para descargar los archivos del escaneo. */
export interface ScanReport {
  /** Reporte completo en JSON; null si el escaneo no lo tiene guardado. */
  report_url: string | null
  /** Inventario criptográfico en CycloneDX 1.6; null si no está guardado. */
  cbom_url: string | null
  /** Segundos que duran las URLs. */
  expires_in: number
}
