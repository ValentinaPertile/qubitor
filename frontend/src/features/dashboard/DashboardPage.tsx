import { FolderGit2, Radar, RefreshCw, ServerCrash } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { EmptyState } from '@/components/EmptyState'
import { FindingsTable } from '@/components/FindingsTable'
import { PageHeader } from '@/components/layout/PageHeader'
import { Skeleton } from '@/components/Loader'
import { ScanProgress } from '@/components/ScanProgress'
import { useToast } from '@/components/toast/toastContext'
import { useScanPolling } from '@/hooks/useScanPolling'
import { USE_MOCKS } from '@/lib/config'
import { formatDateTime, formatNumber } from '@/lib/format'
import { STATUS_LABEL } from '@/lib/labels'
import type { FindingRecord, FindingStatus } from '@/types/Finding'
import type { Scan } from '@/types/Scan'
import { dashboardSource, type DashboardData } from './dataSource'
import { EngineMatrix } from './EngineMatrix'
import { GradeNotice } from './GradeNotice'
import { ModuleShortcuts } from './ModuleShortcuts'
import { PenaltyBreakdown } from './PenaltyBreakdown'
import { computeStats } from './stats'

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'empty' }
  | { status: 'ready'; data: DashboardData }

/** Tiempo que la barra queda en 100 % antes de desaparecer. */
const PROGRESS_LINGER_MS = 1800

export default function DashboardPage() {
  const [state, setState] = useState<LoadState>({ status: 'loading' })
  const [scanId, setScanId] = useState<string | null>(null)
  const [pendingIds, setPendingIds] = useState<ReadonlySet<string>>(new Set())
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const data = await dashboardSource.load()
      setState(data ? { status: 'ready', data } : { status: 'empty' })
    } catch (error) {
      setState({ status: 'error', message: error instanceof Error ? error.message : 'Error desconocido.' })
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const handleScanFinished = useCallback(
    async (scan: Scan) => {
      if (scan.status === 'completed') {
        await load()
        toast({ message: `Escaneo terminado. Nota ${scan.grade ?? '—'}, Risk Score ${formatNumber(scan.risk_score ?? 0)}.` })
      } else if (scan.status === 'failed') {
        toast({ message: scan.error ?? 'El escaneo falló. Intentá de nuevo.', tone: 'error' })
      } else {
        toast({ message: `El escaneo terminó con un estado inesperado (${String(scan.status)}).`, tone: 'error' })
      }
      window.setTimeout(() => setScanId(null), PROGRESS_LINGER_MS)
    },
    [load, toast],
  )

  const { scan: liveScan, error: pollError } = useScanPolling(scanId, {
    fetchScan: dashboardSource.getScan,
    onFinish: handleScanFinished,
  })

  async function startScan(repositoryId: string) {
    try {
      const scan = await dashboardSource.startScan(repositoryId)
      setScanId(scan.id)
    } catch (error) {
      toast({ message: error instanceof Error ? error.message : 'No se pudo iniciar el escaneo.', tone: 'error' })
    }
  }

  const setFindingStatus = useCallback((id: string, status: FindingStatus) => {
    setState((current) =>
      current.status === 'ready'
        ? {
            ...current,
            data: { ...current.data, findings: current.data.findings.map((f) => (f.id === id ? { ...f, status } : f)) },
          }
        : current,
    )
  }, [])

  const changeStatus = useCallback(
    async function change(finding: FindingRecord, status: FindingStatus) {
      const previous = finding.status
      setFindingStatus(finding.id, status)
      setPendingIds((ids) => new Set(ids).add(finding.id))
      try {
        await dashboardSource.updateFinding(finding.id, status)
        toast({
          message:
            status === 'open'
              ? `«${finding.title}» se reabrió.`
              : `«${finding.title}» quedó como ${STATUS_LABEL[status].toLowerCase()}.`,
          action: { label: 'Deshacer', onClick: () => change({ ...finding, status }, previous) },
        })
      } catch (error) {
        setFindingStatus(finding.id, previous)
        toast({
          message: `No se pudo guardar el cambio. ${error instanceof Error ? error.message : ''}`.trim(),
          tone: 'error',
        })
      } finally {
        setPendingIds((ids) => {
          const next = new Set(ids)
          next.delete(finding.id)
          return next
        })
      }
    },
    [setFindingStatus, toast],
  )

  if (state.status === 'loading') return <DashboardSkeleton />

  if (state.status === 'error') {
    return (
      <>
        <PageHeader title="Dashboard general" />
        <EmptyState
          icon={ServerCrash}
          tone="error"
          title="No pudimos cargar el dashboard"
          description={state.message}
          action={
            <button
              type="button"
              onClick={() => {
                setState({ status: 'loading' })
                load()
              }}
              className="inline-flex h-10 items-center gap-2 rounded-sm bg-civic px-4 text-sm font-semibold text-civic-ink hover:bg-civic-deep active:scale-[0.96]"
            >
              <RefreshCw className="size-4" aria-hidden="true" />
              Reintentar
            </button>
          }
        />
      </>
    )
  }

  if (state.status === 'empty') {
    return (
      <>
        <PageHeader title="Dashboard general" />
        <EmptyState
          icon={FolderGit2}
          title="Todavía no conectaste un repositorio"
          description="Conectá un repositorio de GitHub y lanzá el primer escaneo para ver su nota de seguridad."
          action={
            <Link
              to="/connect"
              className="inline-flex h-10 items-center rounded-sm bg-civic px-4 text-sm font-semibold text-civic-ink hover:bg-civic-deep"
            >
              Conectar repositorio
            </Link>
          }
        />
      </>
    )
  }

  const { repository, scan, findings } = state.data
  const scanning = scanId !== null

  return (
    <>
      <PageHeader
        title={repository.full_name.split('/').pop()}
        meta={
          <span className="flex flex-wrap gap-x-2 gap-y-1">
            <a href={repository.url} target="_blank" rel="noreferrer" className="hover:text-civic hover:underline">
              {repository.full_name}
            </a>
            <span>
              <span aria-hidden="true" className="mr-2">·</span>rama <span className="font-mono text-[0.8125rem]">{repository.default_branch}</span>
            </span>
            {scan?.commit_sha && (
              <>
                <span>
                  <span aria-hidden="true" className="mr-2">·</span>commit <span className="font-mono text-[0.8125rem]">{scan.commit_sha}</span>
                </span>
              </>
            )}
            {scan?.finished_at && (
              <>
                <span className="tabular">
                  <span aria-hidden="true" className="mr-2">·</span>último escaneo {formatDateTime(scan.finished_at)}</span>
              </>
            )}
          </span>
        }
        actions={
          <button
            type="button"
            onClick={() => startScan(repository.id)}
            disabled={scanning}
            className="inline-flex h-10 items-center gap-2 rounded-sm bg-civic px-4 text-sm font-semibold text-civic-ink shadow-sheet transition-[background-color,scale,opacity] duration-150 hover:bg-civic-deep active:scale-[0.96] disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Radar className="size-4" strokeWidth={2} aria-hidden="true" />
            {scanning ? 'Escaneando…' : 'Nuevo escaneo'}
          </button>
        }
      />

      <div className="space-y-5 px-4 pb-12 sm:px-8">
        {USE_MOCKS && (
          <p className="text-xs text-ink-3">
            Datos de ejemplo de <code className="font-mono">features/dashboard/mock.json</code>: la API todavía no está conectada.
          </p>
        )}

        {scanning && <ScanProgress scan={liveScan} error={pollError} />}

        {scan ? (
          <DashboardBody scan={scan} findings={findings} onStatusChange={changeStatus} pendingIds={pendingIds} />
        ) : (
          <div className="rounded-sm bg-sheet shadow-sheet ring-1 ring-rule">
            <EmptyState
              icon={Radar}
              title="Este repositorio todavía no tiene escaneos"
              description="Lanzá el primer escaneo para calcular su nota. Tarda alrededor de un minuto."
            />
          </div>
        )}
      </div>
    </>
  )
}

interface DashboardBodyProps {
  scan: Scan
  findings: FindingRecord[]
  onStatusChange: (finding: FindingRecord, status: FindingStatus) => void
  pendingIds: ReadonlySet<string>
}

function DashboardBody({ scan, findings, onStatusChange, pendingIds }: DashboardBodyProps) {
  const stats = useMemo(() => computeStats(findings), [findings])

  return (
    <>
      <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-5 xl:grid-cols-12">
        <div className="contents xl:grid xl:grid-cols-[minmax(0,1fr)] xl:gap-5 xl:col-span-6">
          <GradeNotice
            className="order-1 xl:order-none"
            score={stats.score}
            grade={stats.grade}
            penalty={stats.penalty}
            counted={stats.counted}
            total={findings.length}
            scan={scan}
          />
          <ModuleShortcuts className="order-4 xl:order-none" counts={stats.byView} />
        </div>
        <div className="contents xl:grid xl:grid-cols-[minmax(0,1fr)] xl:gap-5 xl:col-span-6">
          <PenaltyBreakdown className="order-2 xl:order-none" counts={stats.bySeverity} />
          <EngineMatrix className="order-3 xl:order-none" counts={stats.byEngine} />
        </div>
      </div>

      <FindingsTable findings={findings} onStatusChange={onStatusChange} pendingIds={pendingIds} />
    </>
  )
}

function DashboardSkeleton() {
  return (
    <div role="status" aria-label="Cargando el dashboard">
      <div className="space-y-2.5 px-4 pt-9 pb-6 sm:px-8">
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-4 w-96 max-w-full" />
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 px-4 sm:px-8 xl:grid-cols-12">
        <Skeleton className="h-[22rem] xl:col-span-6" />
        <Skeleton className="h-[22rem] xl:col-span-6" />
        <Skeleton className="h-64 xl:col-span-12" />
      </div>
    </div>
  )
}
