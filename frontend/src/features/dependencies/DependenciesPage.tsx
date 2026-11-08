import { Copy, FolderGit2, PackageCheck, Radar, RefreshCw, ServerCrash } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Skeleton } from '@/components/Loader'
import { useToast } from '@/components/toast/toastContext'
import { USE_MOCKS } from '@/lib/config'
import { formatDateTime, pluralize } from '@/lib/format'
import { ReportDownloadButton } from '@/features/pqc/ReportDownloadButton'
import { loadDependencies, type DependenciesData } from './dataSource'
import { PackageTable } from './PackageTable'
import { combinedCommands, groupByPackage } from './packages'

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'empty' }
  | { status: 'ready'; data: DependenciesData }

/** Vista «Dependencias» (Módulo D): paquetes con vulnerabilidades conocidas según OSV. */
export default function DependenciesPage() {
  const [state, setState] = useState<LoadState>({ status: 'loading' })
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const data = await loadDependencies()
      setState(data ? { status: 'ready', data } : { status: 'empty' })
    } catch (error) {
      setState({ status: 'error', message: error instanceof Error ? error.message : 'Error desconocido.' })
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const copy = useCallback(
    async (command: string) => {
      try {
        await navigator.clipboard.writeText(command)
        toast({ message: 'Comando copiado.' })
      } catch {
        toast({ message: 'No se pudo copiar. Seleccioná el comando y copialo a mano.', tone: 'error' })
      }
    },
    [toast],
  )

  if (state.status === 'loading') return <DependenciesSkeleton />

  if (state.status === 'error') {
    return (
      <>
        <PageHeader title="Dependencias" />
        <EmptyState
          icon={ServerCrash}
          tone="error"
          title="No pudimos cargar las dependencias"
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
        <PageHeader title="Dependencias" />
        <EmptyState
          icon={FolderGit2}
          title="Todavía no conectaste un repositorio"
          description="Conectá un repositorio y escanealo para ver qué dependencias tienen vulnerabilidades conocidas."
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

  return <DependenciesView data={state.data} onCopy={copy} />
}

function DependenciesView({ data, onCopy }: { data: DependenciesData; onCopy: (command: string) => void }) {
  const { repository, scan, findings } = data
  const groups = useMemo(() => groupByPackage(findings), [findings])
  const commands = useMemo(() => combinedCommands(groups), [groups])
  const pending = groups.reduce((sum, g) => sum + g.pendingCount, 0)
  const vulnerablePackages = groups.filter((g) => g.pendingCount > 0).length

  return (
    <>
      <PageHeader
        title="Dependencias"
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
        actions={
          <>
            {scan && <ReportDownloadButton scanId={scan.id} kind="report" label="Descargar reporte" />}
            {commands.length > 0 && (
              <button
                type="button"
                onClick={() => onCopy(commands.join('\n'))}
                className="inline-flex h-10 items-center gap-2 rounded-sm bg-civic px-4 text-sm font-semibold text-civic-ink shadow-sheet transition-[background-color,scale] duration-150 hover:bg-civic-deep active:scale-[0.96]"
              >
                <Copy className="size-4" strokeWidth={2} aria-hidden="true" />
                Copiar todos los comandos
              </button>
            )}
          </>
        }
      />

      <div className="space-y-5 px-4 pb-12 sm:px-8">
        {USE_MOCKS && (
          <p className="text-xs text-ink-3">
            Datos de ejemplo de <code className="font-mono">features/dependencies/mock.json</code>: la API todavía no está conectada.
          </p>
        )}

        {scan === null ? (
          <div className="rounded-sm bg-sheet shadow-sheet ring-1 ring-rule">
            <EmptyState
              icon={Radar}
              title="Este repositorio todavía no tiene escaneos"
              description="Lanzá un escaneo desde el dashboard para revisar sus dependencias."
              action={
                <Link to="/" className="text-sm font-semibold text-civic underline decoration-civic/30 hover:decoration-civic">
                  Ir al dashboard
                </Link>
              }
            />
          </div>
        ) : groups.length === 0 ? (
          <div className="rounded-sm bg-sheet shadow-sheet ring-1 ring-rule">
            <EmptyState
              icon={PackageCheck}
              title="Ninguna dependencia con vulnerabilidades conocidas"
              description="OSV no tiene fallas registradas para las versiones de requirements.txt, package.json y package-lock.json de este repositorio."
            />
          </div>
        ) : (
          <>
            <p className="max-w-[75ch] text-sm text-ink-2">
              <strong className="font-semibold text-ink tabular">{pluralize(pending, 'vulnerabilidad pendiente', 'vulnerabilidades pendientes')}</strong>{' '}
              en {pluralize(vulnerablePackages, 'paquete', 'paquetes')}. Para cada paquete se propone la versión que corrige
              todas sus fallas conocidas, no solo la primera.
            </p>
            <PackageTable groups={groups} onCopy={onCopy} />
          </>
        )}
      </div>
    </>
  )
}

function DependenciesSkeleton() {
  return (
    <div role="status" aria-label="Cargando las dependencias">
      <div className="space-y-2.5 px-4 pt-9 pb-6 sm:px-8">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-4 w-80 max-w-full" />
      </div>
      <div className="space-y-5 px-4 sm:px-8">
        <Skeleton className="h-4 w-96 max-w-full" />
        <Skeleton className="h-72" />
      </div>
    </div>
  )
}
