import { ChevronDown, Search, SearchX } from 'lucide-react'
import { useId, useMemo, useState } from 'react'
import { ENGINE_LABEL, SEVERITY_LABEL } from '@/lib/labels'
import { cn } from '@/lib/cn'
import { effectiveSeverity, isInformational } from '@/lib/risk'
import { ENGINES, SEVERITIES, type EngineName, type FindingRecord, type FindingStatus, type Severity } from '@/types/Finding'
import { EmptyState } from './EmptyState'
import { FindingCard } from './FindingCard'
import { FindingStatusActions } from './FindingStatusActions'
import { SeverityBadge } from './SeverityBadge'
import { StatusStamp } from './StatusStamp'

type StatusFilter = 'all' | FindingStatus

const STATUS_TABS: { id: StatusFilter; label: string }[] = [
  { id: 'all', label: 'Todos' },
  { id: 'open', label: 'Abiertos' },
  { id: 'resolved', label: 'Resueltos' },
  { id: 'false_positive', label: 'Falsos positivos' },
]

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

interface FindingsTableProps {
  findings: readonly FindingRecord[]
  /** Si se pasa, cada hallazgo expandido muestra los botones de estado. */
  onStatusChange?: (finding: FindingRecord, status: FindingStatus) => void
  /** Hallazgos con un cambio de estado en curso. */
  pendingIds?: ReadonlySet<string>
  /** Motores a mostrar en el filtro; por defecto, los cuatro. */
  engines?: readonly EngineName[]
  initialStatus?: StatusFilter
  title?: string
  className?: string
}

/** Tabla de hallazgos con filtros por estado, severidad, motor y texto. */
export function FindingsTable({
  findings,
  onStatusChange,
  pendingIds,
  engines = ENGINES,
  initialStatus = 'all',
  title = 'Hallazgos',
  className,
}: FindingsTableProps) {
  const [status, setStatus] = useState<StatusFilter>(initialStatus)
  const [severities, setSeverities] = useState<ReadonlySet<Severity>>(new Set())
  const [engine, setEngine] = useState<EngineName | 'all'>('all')
  const [query, setQuery] = useState('')
  const [openId, setOpenId] = useState<string | null>(null)
  const ids = useId()

  // El orden depende solo de la severidad y la ubicación: al cambiar el estado
  // de un hallazgo, la fila queda en su lugar.
  const sorted = useMemo(
    () =>
      [...findings].sort(
        (a, b) =>
          SEVERITY_RANK[effectiveSeverity(a)] - SEVERITY_RANK[effectiveSeverity(b)] ||
          a.file_path.localeCompare(b.file_path) ||
          (a.line ?? 0) - (b.line ?? 0),
      ),
    [findings],
  )

  const statusCounts = useMemo(() => {
    const counts: Record<StatusFilter, number> = { all: findings.length, open: 0, resolved: 0, false_positive: 0 }
    // Los info no tienen estado que gestionar: solo cuentan en «Todos».
    for (const f of findings) if (!isInformational(f)) counts[f.status] += 1
    return counts
  }, [findings])

  const needle = query.trim().toLowerCase()
  const visible = sorted.filter(
    (f) =>
      (status === 'all' || (!isInformational(f) && f.status === status)) &&
      (severities.size === 0 || severities.has(effectiveSeverity(f))) &&
      (engine === 'all' || f.engine === engine) &&
      (needle === '' || `${f.title} ${f.file_path} ${f.rule_id} ${f.cve ?? ''}`.toLowerCase().includes(needle)),
  )

  const filtersActive = status !== 'all' || severities.size > 0 || engine !== 'all' || needle !== ''

  function toggleSeverity(severity: Severity) {
    setSeverities((current) => {
      const next = new Set(current)
      if (next.has(severity)) next.delete(severity)
      else next.add(severity)
      return next
    })
  }

  function clearFilters() {
    setStatus('all')
    setSeverities(new Set())
    setEngine('all')
    setQuery('')
  }

  return (
    <section aria-labelledby={`${ids}-title`} className={cn('rounded-sm bg-sheet shadow-sheet ring-1 ring-rule', className)}>
      <header className="space-y-4 border-b border-rule px-4 pt-5 pb-4 sm:px-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id={`${ids}-title`} className="text-lg font-semibold text-ink">
            {title}
          </h2>
          <p className="text-sm text-ink-2 tabular" aria-live="polite">
            {visible.length === findings.length
              ? `${findings.length} hallazgos`
              : `${visible.length} de ${findings.length} hallazgos`}
          </p>
        </div>

        <div role="tablist" aria-label="Estado" className="flex flex-wrap gap-1">
          {STATUS_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={status === tab.id}
              onClick={() => setStatus(tab.id)}
              className={cn(
                'inline-flex h-9 shrink-0 items-center gap-2 rounded-sm px-3 text-sm transition-[background-color,color] duration-150',
                status === tab.id ? 'bg-civic font-semibold text-civic-ink' : 'text-ink-2 hover:bg-civic-soft hover:text-ink',
              )}
            >
              {tab.label}
              <span className={cn('tabular text-xs', status === tab.id ? 'text-civic-muted' : 'text-ink-3')}>
                {statusCounts[tab.id]}
              </span>
            </button>
          ))}
        </div>

        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <div role="group" aria-label="Severidad" className="flex flex-wrap gap-1.5">
            {SEVERITIES.map((severity) => {
              const active = severities.has(severity)
              return (
                <button
                  key={severity}
                  type="button"
                  aria-pressed={active}
                  onClick={() => toggleSeverity(severity)}
                  className={cn(
                    'inline-flex h-8 items-center rounded-sm px-2.5 text-[0.8125rem] font-medium ring-1 ring-inset transition-[background-color,color,box-shadow] duration-150',
                    active ? 'bg-ink text-white ring-ink' : 'text-ink-2 ring-rule-2 hover:bg-civic-soft hover:text-ink',
                  )}
                >
                  {SEVERITY_LABEL[severity]}
                </button>
              )
            })}
          </div>

          <div className="flex flex-1 flex-col gap-2 sm:flex-row lg:justify-end">
            <label className="relative block">
              <span className="sr-only">Motor</span>
              <select
                value={engine}
                onChange={(event) => setEngine(event.target.value as EngineName | 'all')}
                className="h-9 w-full appearance-none rounded-sm bg-sheet pr-9 pl-3 text-sm text-ink ring-1 ring-rule-2 ring-inset hover:ring-ink-3 sm:w-44"
              >
                <option value="all">Todos los motores</option>
                {engines.map((name) => (
                  <option key={name} value={name}>
                    {ENGINE_LABEL[name]}
                  </option>
                ))}
              </select>
              <ChevronDown className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-ink-3" aria-hidden="true" />
            </label>
            <label className="relative block">
              <span className="sr-only">Buscar</span>
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ink-3" aria-hidden="true" />
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Buscar título, archivo o CVE"
                className="h-9 w-full rounded-sm bg-sheet pr-3 pl-9 text-sm text-ink ring-1 ring-rule-2 ring-inset placeholder:text-ink-3 hover:ring-ink-3 sm:w-64"
              />
            </label>
          </div>
        </div>
      </header>

      {visible.length === 0 ? (
        <EmptyState
          icon={SearchX}
          title={findings.length === 0 ? 'Sin hallazgos' : 'Ningún hallazgo coincide con los filtros'}
          description={
            findings.length === 0
              ? 'El escaneo no encontró problemas en este repositorio.'
              : 'Probá con otra severidad o motor, o limpiá los filtros para ver todo.'
          }
          action={
            filtersActive && (
              <button
                type="button"
                onClick={clearFilters}
                className="text-sm font-semibold text-civic underline decoration-civic/30 hover:decoration-civic"
              >
                Limpiar filtros
              </button>
            )
          }
        />
      ) : (
        <>
          <div
            aria-hidden="true"
            className="hidden grid-cols-[6.5rem_minmax(0,1fr)_minmax(0,15rem)_7.5rem_8.5rem_1.25rem] gap-4 border-b border-rule bg-paper/60 px-5 py-2 md:grid"
          >
            {['Severidad', 'Hallazgo', 'Ubicación', 'Motor', 'Estado', ''].map((label) => (
              <span key={label} className="field-label">
                {label}
              </span>
            ))}
          </div>
          <ul className="divide-y divide-rule">
            {visible.map((finding) => (
              <FindingRow
                key={finding.id}
                finding={finding}
                open={openId === finding.id}
                onToggle={() => setOpenId((current) => (current === finding.id ? null : finding.id))}
                onStatusChange={onStatusChange}
                pending={pendingIds?.has(finding.id) ?? false}
              />
            ))}
          </ul>
        </>
      )}
    </section>
  )
}

interface FindingRowProps {
  finding: FindingRecord
  open: boolean
  onToggle: () => void
  onStatusChange?: (finding: FindingRecord, status: FindingStatus) => void
  pending: boolean
}

function FindingRow({ finding, open, onToggle, onStatusChange, pending }: FindingRowProps) {
  const panelId = useId()
  const informational = isInformational(finding)
  const closed = !informational && finding.status !== 'open'
  const severity = effectiveSeverity(finding)

  return (
    <li className="t-acc" data-open={open}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={onToggle}
        className={cn(
          'grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 px-4 py-3.5 text-left transition-colors duration-150 hover:bg-civic-soft/50 sm:px-5 md:grid-cols-[6.5rem_minmax(0,1fr)_minmax(0,15rem)_7.5rem_8.5rem_1.25rem]',
          open && 'bg-civic-soft/50',
        )}
      >
        <span className={cn('col-start-1 row-start-1 md:col-auto md:row-auto', closed && 'opacity-55')}>
          <SeverityBadge severity={severity} />
        </span>
        <span className="col-span-2 row-start-2 min-w-0 md:col-span-1 md:row-auto">
          <span
            className={cn(
              'block font-medium text-ink',
              closed && 'text-ink-3 line-through decoration-ink-3/60',
            )}
          >
            {finding.title}
          </span>
          <span className="mt-0.5 block truncate font-mono text-xs text-ink-3">{finding.rule_id}</span>
        </span>
        <span className="hidden min-w-0 truncate font-mono text-[0.8125rem] text-ink-2 md:block">
          {finding.file_path}
          {finding.line != null && `:${finding.line}`}
        </span>
        <span className="hidden text-sm text-ink-2 md:block">{ENGINE_LABEL[finding.engine]}</span>
        <span className="row-start-3 md:row-auto">
          {!informational && <StatusStamp status={finding.status} />}
        </span>
        <span className="t-acc-chevron col-start-2 row-start-1 justify-self-end text-ink-3 md:col-auto md:row-auto">
          <ChevronDown className="size-5" strokeWidth={1.75} aria-hidden="true" />
        </span>
      </button>

      <div id={panelId} className="t-acc-panel" inert={!open}>
        <div className="t-acc-panel-inner">
          <div className="border-t border-rule bg-paper/40 px-4 py-5 sm:px-5 md:pl-[8.75rem]">
            <FindingCard
              finding={finding}
              hideHeader
              actions={
                onStatusChange &&
                !informational && (
                  <FindingStatusActions
                    finding={finding}
                    pending={pending}
                    onChange={(status) => onStatusChange(finding, status)}
                  />
                )
              }
            />
          </div>
        </div>
      </div>
    </li>
  )
}
