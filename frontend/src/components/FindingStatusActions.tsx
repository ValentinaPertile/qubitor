import { Ban, Check, RotateCcw } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { isInformational } from '@/lib/risk'
import type { FindingRecord, FindingStatus } from '@/types/Finding'

interface FindingStatusActionsProps {
  finding: FindingRecord
  onChange: (status: FindingStatus) => void
  /** Deshabilita los botones mientras se guarda el cambio. */
  pending?: boolean
}

/**
 * Botones para marcar un hallazgo como resuelto o falso positivo, o reabrirlo.
 * Los hallazgos info no son fallas reales: no tienen estado que gestionar.
 */
export function FindingStatusActions({ finding, onChange, pending = false }: FindingStatusActionsProps) {
  if (isInformational(finding)) return null
  if (finding.status !== 'open') {
    return (
      <ActionButton icon={<RotateCcw />} onClick={() => onChange('open')} disabled={pending}>
        Reabrir
      </ActionButton>
    )
  }
  return (
    <div className="flex flex-wrap gap-2">
      <ActionButton icon={<Check />} onClick={() => onChange('resolved')} disabled={pending} primary>
        Marcar resuelto
      </ActionButton>
      <ActionButton icon={<Ban />} onClick={() => onChange('false_positive')} disabled={pending}>
        Falso positivo
      </ActionButton>
    </div>
  )
}

interface ActionButtonProps {
  icon: ReactNode
  children: ReactNode
  onClick: () => void
  disabled?: boolean
  primary?: boolean
}

function ActionButton({ icon, children, onClick, disabled, primary }: ActionButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'inline-flex h-9 items-center gap-1.5 rounded-sm px-3 text-sm font-semibold transition-[background-color,scale,box-shadow] duration-150 active:scale-[0.96] disabled:cursor-not-allowed disabled:opacity-60 [&_svg]:size-4 [&_svg]:stroke-2',
        primary
          ? 'bg-civic text-civic-ink hover:bg-civic-deep'
          : 'bg-sheet text-ink ring-1 ring-rule-2 ring-inset hover:bg-civic-soft',
      )}
    >
      <span aria-hidden="true">{icon}</span>
      {children}
    </button>
  )
}
