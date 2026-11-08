import { FolderGit2, KeyRound, Radar, RefreshCw, ServerCrash } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Skeleton } from '@/components/Loader'
import { USE_MOCKS } from '@/lib/config'
import { formatDateTime } from '@/lib/format'
import { CbomTable } from './CbomTable'
import { loadPqc, type PqcData } from './dataSource'
import { ExposureCard } from './ExposureCard'
import { MigrationRoadmap } from './MigrationRoadmap'
import { ReportDownloadButton } from './ReportDownloadButton'
import { cryptoUsages, exposure, migrationRoadmap } from './quantum'

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'empty' }
  | { status: 'ready'; data: PqcData }

const TITLE = 'Preparación post-cuántica'

/** Vista «Preparación post-cuántica» (Módulo D): CBOM, exposición a Shor y hoja de ruta. */
export default function PqcPage() {
  const [state, setState] = useState<LoadState>({ status: 'loading' })

  const load = useCallback(async () => {
    try {
      const data = await loadPqc()
      setState(data ? { status: 'ready', data } : { status: 'empty' })
    } catch (error) {
      setState({ status: 'error', message: error instanceof Error ? error.message : 'Error desconocido.' })
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  if (state.status === 'loading') return <PqcSkeleton />

  if (state.status === 'error') {
    return (
      <>
        <PageHeader title={TITLE} />
        <EmptyState
          icon={ServerCrash}
          tone="error"
          title="No pudimos cargar el inventario criptográfico"
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
        <PageHeader title={TITLE} />
        <EmptyState
          icon={FolderGit2}
          title="Todavía no conectaste un repositorio"
          description="Conectá un repositorio y escanealo para ver qué criptografía usa y cuánto de ella rompería una computadora cuántica."
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

  return <PqcView data={state.data} />
}

function PqcView({ data }: { data: PqcData }) {
  const { repository, scan, findings } = data
  const usages = useMemo(() => cryptoUsages(findings), [findings])
  const summary = useMemo(() => exposure(usages), [usages])
  const steps = useMemo(() => migrationRoadmap(usages), [usages])

  return (
    <>
      <PageHeader
        title={TITLE}
        meta={
          <span className="flex flex-wrap gap-x-2 gap-y-1">
            <span>{repository.full_name}</span>
            {scan?.finished_at && (
              <span className="tabular">
                <span aria-hidden="true" className="mr-2">·</span>último escaneo {formatDateTime(scan.finished_at)}
              </span>
            )}
          </span>
        }
        actions={scan && <ReportDownloadButton scanId={scan.id} kind="cbom" label="Descargar CBOM (CycloneDX)" />}
      />

      <div className="space-y-5 px-4 pb-12 sm:px-8">
        {USE_MOCKS && (
          <p className="text-xs text-ink-3">
            Datos de ejemplo de <code className="font-mono">features/pqc/mock.json</code>: la API todavía no está conectada.
          </p>
        )}

        {scan === null ? (
          <div className="rounded-sm bg-sheet shadow-sheet ring-1 ring-rule">
            <EmptyState
              icon={Radar}
              title="Este repositorio todavía no tiene escaneos"
              description="Lanzá un escaneo desde el dashboard para armar su inventario criptográfico."
              action={
                <Link to="/" className="text-sm font-semibold text-civic underline decoration-civic/30 hover:decoration-civic">
                  Ir al dashboard
                </Link>
              }
            />
          </div>
        ) : usages.length === 0 ? (
          <div className="rounded-sm bg-sheet shadow-sheet ring-1 ring-rule">
            <EmptyState
              icon={KeyRound}
              title="No se detectó uso de criptografía"
              description="El escaneo no encontró llamadas a librerías criptográficas en el código Python ni JavaScript de este repositorio."
            />
          </div>
        ) : (
          <>
            <div className="grid gap-5 xl:grid-cols-12">
              <ExposureCard summary={summary} className="xl:col-span-5 xl:self-start" />
              <MigrationRoadmap steps={steps} className="xl:col-span-7" />
            </div>
            <CbomTable usages={usages} />
          </>
        )}
      </div>
    </>
  )
}

function PqcSkeleton() {
  return (
    <div role="status" aria-label="Cargando el inventario criptográfico">
      <div className="space-y-2.5 px-4 pt-9 pb-6 sm:px-8">
        <Skeleton className="h-8 w-72 max-w-full" />
        <Skeleton className="h-4 w-80 max-w-full" />
      </div>
      <div className="space-y-5 px-4 sm:px-8">
        <div className="grid gap-5 xl:grid-cols-12">
          <Skeleton className="h-80 xl:col-span-5" />
          <Skeleton className="h-80 xl:col-span-7" />
        </div>
        <Skeleton className="h-64" />
      </div>
    </div>
  )
}
