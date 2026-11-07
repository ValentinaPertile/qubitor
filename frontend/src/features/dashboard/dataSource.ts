import { api } from '@/lib/api'
import { USE_MOCKS } from '@/lib/config'
import { gradeFor, riskScore } from '@/lib/risk'
import type { FindingRecord, FindingStatus } from '@/types/Finding'
import { SCAN_STAGES, type Repository, type Scan } from '@/types/Scan'
import mock from './mock.json'

export interface DashboardData {
  repository: Repository
  /** Último escaneo terminado; null si el repo todavía no se escaneó. */
  scan: Scan | null
  findings: FindingRecord[]
}

/** De dónde saca el dashboard sus datos: la API real o los mocks. */
export interface DashboardSource {
  /** null cuando la organización no conectó ningún repositorio. */
  load: () => Promise<DashboardData | null>
  startScan: (repositoryId: string) => Promise<Scan>
  getScan: (scanId: string) => Promise<Scan>
  updateFinding: (findingId: string, status: FindingStatus) => Promise<FindingRecord>
}

const apiSource: DashboardSource = {
  async load() {
    const [repository] = await api.listRepositories()
    if (!repository) return null
    const history = await api.repositoryHistory(repository.id)
    const scan = history.find((s) => s.status === 'completed') ?? null
    const findings = scan ? await api.getScanFindings(scan.id) : []
    return { repository, scan, findings }
  },
  startScan: api.startScan,
  getScan: api.getScan,
  updateFinding: api.updateFinding,
}

/* ---------- Mocks: mismo formato que la API, con un escaneo simulado ---------- */

const MOCK_LATENCY_MS = 450
const MOCK_QUEUE_MS = 1600
const MOCK_SCAN_MS = 9000

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const clone = <T>(value: T): T => structuredClone(value)

const mockState = {
  repository: mock.repository as Repository,
  scan: mock.scan as Scan,
  findings: mock.findings as FindingRecord[],
  running: null as { id: string; startedAt: number } | null,
}

function simulatedScan(id: string, startedAt: number): Scan {
  const elapsed = Date.now() - startedAt
  const base: Scan = {
    ...mockState.scan,
    id,
    status: 'queued',
    progress: null,
    stage: null,
    started_at: new Date(startedAt).toISOString(),
    finished_at: null,
    risk_score: null,
    grade: null,
  }
  if (elapsed < MOCK_QUEUE_MS) return base

  const progress = Math.min(100, ((elapsed - MOCK_QUEUE_MS) / MOCK_SCAN_MS) * 100)
  if (progress < 100) {
    const stage = SCAN_STAGES[Math.min(SCAN_STAGES.length - 1, Math.floor((progress / 100) * SCAN_STAGES.length))]
    return { ...base, status: 'running', progress, stage }
  }

  const score = riskScore(mockState.findings)
  return {
    ...base,
    status: 'completed',
    progress: 100,
    stage: 'persist',
    finished_at: new Date(startedAt + MOCK_QUEUE_MS + MOCK_SCAN_MS).toISOString(),
    risk_score: score,
    grade: gradeFor(score),
  }
}

const mockSource: DashboardSource = {
  async load() {
    await wait(MOCK_LATENCY_MS)
    return {
      repository: clone(mockState.repository),
      scan: clone(mockState.scan),
      findings: clone(mockState.findings),
    }
  },
  async startScan() {
    await wait(MOCK_LATENCY_MS / 2)
    const number = Number(mockState.scan.id.replace(/\D/g, '')) + 1
    mockState.running = { id: `scan_${String(number).padStart(4, '0')}`, startedAt: Date.now() }
    return simulatedScan(mockState.running.id, mockState.running.startedAt)
  },
  async getScan(scanId) {
    await wait(120)
    if (mockState.running?.id !== scanId) {
      if (mockState.scan.id === scanId) return clone(mockState.scan)
      throw new Error('El escaneo no existe.')
    }
    const scan = simulatedScan(scanId, mockState.running.startedAt)
    if (scan.status === 'completed') {
      mockState.scan = scan
      mockState.findings = mockState.findings.map((f) => ({ ...f, scan_id: scan.id }))
      mockState.running = null
    }
    return clone(scan)
  },
  async updateFinding(findingId, status) {
    await wait(250)
    const finding = mockState.findings.find((f) => f.id === findingId)
    if (!finding) throw new Error('El hallazgo no existe.')
    finding.status = status
    return clone(finding)
  },
}

export const dashboardSource: DashboardSource = USE_MOCKS ? mockSource : apiSource
