import { ExternalLink, Sparkles } from 'lucide-react'
import type { ReactNode } from 'react'
import { ENGINE_LABEL } from '@/lib/labels'
import { cn } from '@/lib/cn'
import { effectiveSeverity, isInformational } from '@/lib/risk'
import type { FindingRecord } from '@/types/Finding'
import { CodeSnippet } from './CodeSnippet'
import { SeverityBadge } from './SeverityBadge'
import { StatusStamp } from './StatusStamp'

interface FindingCardProps {
  finding: FindingRecord
  /** Acciones al pie, por ejemplo <FindingStatusActions>. */
  actions?: ReactNode
  /** Sin encabezado: para cuando la fila de la tabla ya muestra título y severidad. */
  hideHeader?: boolean
  className?: string
}

/** Detalle de un hallazgo: ubicación, descripción, código y triage de la IA. */
export function FindingCard({ finding, actions, hideHeader = false, className }: FindingCardProps) {
  const severity = effectiveSeverity(finding)
  const adjusted = finding.triage != null && finding.triage.adjusted_severity !== finding.severity

  return (
    <article className={cn('space-y-5', className)}>
      {!hideHeader && (
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-1.5">
            <SeverityBadge severity={severity} />
            <h3 className="text-base font-semibold text-ink">{finding.title}</h3>
            <p className="font-mono text-xs text-ink-3">{finding.rule_id}</p>
          </div>
          {!isInformational(finding) && <StatusStamp status={finding.status} />}
        </header>
      )}

      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-4">
        <Field label="Archivo">
          <span className="font-mono text-[0.8125rem] break-all">
            {finding.file_path}
            {finding.line != null && `:${finding.line}`}
          </span>
        </Field>
        <Field label="Motor">{ENGINE_LABEL[finding.engine]}</Field>
        {finding.cwe && (
          <Field label="CWE">
            <ReferenceLink href={cweUrl(finding.cwe)}>{finding.cwe}</ReferenceLink>
          </Field>
        )}
        {finding.cve && (
          <Field label="CVE">
            <ReferenceLink href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}>{finding.cve}</ReferenceLink>
          </Field>
        )}
        {adjusted && (
          <Field label="Severidad del motor">
            <SeverityBadge severity={finding.severity} size="sm" />
          </Field>
        )}
      </dl>

      <p className="max-w-[75ch] text-sm text-ink-2">{finding.description}</p>

      {finding.snippet && <CodeSnippet code={finding.snippet} line={finding.line} filePath={finding.file_path} />}

      {finding.triage && (
        <section aria-label="Evaluación de la IA" className="space-y-3 rounded-sm bg-civic-soft/60 p-4 ring-1 ring-civic/10">
          <div className="flex flex-wrap items-center gap-2">
            <Sparkles className="size-4 text-civic" strokeWidth={1.75} aria-hidden="true" />
            <h4 className="text-sm font-semibold text-ink">Evaluación de la IA</h4>
            {finding.triage.is_false_positive && (
              <span className="rounded-xs bg-stamp/10 px-1.5 py-0.5 text-xs font-semibold text-stamp">
                Posible falso positivo
              </span>
            )}
          </div>
          <p className="max-w-[75ch] text-sm text-ink-2">{finding.triage.explanation}</p>
          {finding.triage.remediation && (
            <div>
              <p className="field-label mb-1">Remediación sugerida</p>
              <p className="max-w-[75ch] text-sm whitespace-pre-line text-ink">{finding.triage.remediation}</p>
            </div>
          )}
        </section>
      )}

      {actions && <footer className="pt-1">{actions}</footer>}
    </article>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="field-label mb-0.5">{label}</dt>
      <dd className="text-ink">{children}</dd>
    </div>
  )
}

function ReferenceLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 font-medium text-civic underline decoration-civic/30 hover:decoration-civic"
    >
      {children}
      <ExternalLink className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
      <span className="sr-only">(se abre en otra pestaña)</span>
    </a>
  )
}

function cweUrl(cwe: string): string {
  const id = cwe.replace(/^CWE-/i, '')
  return `https://cwe.mitre.org/data/definitions/${id}.html`
}
