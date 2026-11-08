import { Download } from 'lucide-react'
import { useState } from 'react'
import { useToast } from '@/components/toast/toastContext'
import { api, ApiError } from '@/lib/api'
import { USE_MOCKS } from '@/lib/config'

/**
 * Descarga un archivo del escaneo guardado en R2 (Módulo D): el reporte JSON o
 * el CBOM en CycloneDX. La URL firmada vence a los pocos minutos, así que se
 * pide recién al hacer clic. Con datos de ejemplo no hay nada que descargar.
 */
export function ReportDownloadButton({
  scanId,
  kind,
  label,
}: {
  scanId: string
  kind: 'report' | 'cbom'
  label: string
}) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)

  if (USE_MOCKS) return null

  const download = async () => {
    setBusy(true)
    try {
      const report = await api.getScanReport(scanId)
      const url = kind === 'cbom' ? report.cbom_url : report.report_url
      if (!url) {
        toast({ message: 'Este escaneo no tiene el archivo guardado.', tone: 'error' })
        return
      }
      // El archivo se guarda como descarga: el navegador lo baja sin salir de la página.
      window.location.assign(url)
    } catch (error) {
      const message =
        error instanceof ApiError && error.status === 503
          ? 'La descarga de reportes no está disponible en este momento.'
          : error instanceof Error
            ? error.message
            : 'No se pudo descargar el archivo.'
      toast({ message, tone: 'error' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <button
      type="button"
      onClick={download}
      disabled={busy}
      aria-busy={busy}
      className="inline-flex h-10 items-center gap-2 rounded-sm bg-sheet px-4 text-sm font-semibold text-ink shadow-sheet ring-1 ring-rule-2 ring-inset transition-[background-color,scale] duration-150 hover:bg-paper active:scale-[0.96] disabled:opacity-60"
    >
      <Download className="size-4" strokeWidth={2} aria-hidden="true" />
      {label}
    </button>
  )
}
