import { Check, TriangleAlert } from 'lucide-react'
import { STAGE_LABEL } from '@/lib/labels'
import { cn } from '@/lib/cn'
import { SCAN_STAGES, type Scan } from '@/types/Scan'

interface ScanProgressProps {
  /** Último estado leído de /scans/{id}; null mientras llega la primera respuesta. */
  scan: Scan | null
  /** Error de red del polling (el escaneo puede seguir corriendo). */
  error?: string | null
  className?: string
}

/** Barra de progreso del escaneo con las etapas del pipeline. */
export function ScanProgress({ scan, error, className }: ScanProgressProps) {
  const queued = scan === null || scan.status === 'queued'
  const failed = scan?.status === 'failed'
  const progress = scan?.status === 'completed' ? 100 : Math.round(scan?.progress ?? 0)
  const currentIndex = scan?.stage ? SCAN_STAGES.indexOf(scan.stage) : -1

  const headline = failed
    ? 'El escaneo falló'
    : scan?.status === 'completed'
      ? 'Escaneo terminado'
      : queued
        ? 'En cola, esperando un worker libre…'
        : `Escaneando · ${STAGE_LABEL[scan.stage ?? 'clone']}`

  return (
    <section
      aria-label="Progreso del escaneo"
      className={cn('t-reveal rounded-sm bg-sheet px-4 py-4 shadow-sheet ring-1 ring-rule sm:px-5', className)}
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className={cn('text-sm font-semibold', failed ? 'text-sev-critical' : 'text-ink')}>{headline}</p>
        {!queued && !failed && <p className="font-display text-xl leading-none font-semibold text-civic tabular">{progress}%</p>}
      </div>

      <div
        role="progressbar"
        aria-label="Avance del escaneo"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={queued ? undefined : progress}
        aria-valuetext={headline}
        className="relative mt-3 h-2 overflow-hidden rounded-full bg-civic-soft"
      >
        {queued ? (
          <div className="t-indeterminate absolute inset-y-0 w-2/5 rounded-full bg-civic/50" />
        ) : (
          <div
            className={cn(
              'h-full origin-left rounded-full transition-[width] duration-700 ease-(--ease-swift)',
              failed ? 'bg-sev-critical' : 'bg-civic',
            )}
            style={{ width: `${progress}%` }}
          />
        )}
      </div>

      <ol className="mt-3.5 grid grid-cols-3 gap-x-3 gap-y-1.5 sm:grid-cols-6">
        {SCAN_STAGES.map((stage, index) => {
          const done = scan?.status === 'completed' || index < currentIndex
          const active = !done && index === currentIndex && scan?.status === 'running'
          return (
            <li
              key={stage}
              aria-current={active ? 'step' : undefined}
              className={cn(
                'flex items-center gap-1.5 text-xs',
                done ? 'text-ink-2' : active ? 'font-semibold text-civic' : 'text-ink-3',
              )}
            >
              <span
                aria-hidden="true"
                className={cn(
                  'grid size-4 shrink-0 place-items-center rounded-full ring-1 ring-inset',
                  done ? 'bg-civic text-civic-ink ring-civic' : active ? 'ring-civic' : 'ring-rule-2',
                )}
              >
                {done && <Check className="size-2.5" strokeWidth={3} />}
                {active && <span className="size-1.5 animate-pulse rounded-full bg-civic motion-reduce:animate-none" />}
              </span>
              {STAGE_LABEL[stage]}
            </li>
          )
        })}
      </ol>

      {(error || (failed && scan?.error)) && (
        <p role="alert" className="mt-3 flex items-start gap-2 text-sm text-sev-critical">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          {failed ? scan?.error : `${error} Reintentando…`}
        </p>
      )}
    </section>
  )
}
