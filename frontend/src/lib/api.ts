import type { FindingRecord, FindingStatus } from '@/types/Finding'
import type { Repository, Scan, ScanReport } from '@/types/Scan'
import { API_URL } from './config'

/**
 * Cliente unificado de la API de Qubitor. Todas las vistas lo usan, así el
 * token de Clerk, los errores y la URL base se resuelven en un solo lugar.
 */

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

type TokenGetter = () => Promise<string | null>

let getToken: TokenGetter = async () => null

/** Lo llama el proveedor de auth para adjuntar el JWT de Clerk a cada request. */
export function setTokenGetter(getter: TokenGetter): void {
  getToken = getter
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await getToken()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body !== undefined) headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)

  let response: Response
  try {
    response = await fetch(`${API_URL}${path}`, { ...init, headers })
  } catch {
    throw new ApiError(0, 'No se pudo conectar con la API. Revisá tu conexión e intentá de nuevo.')
  }

  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response))
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

/** FastAPI devuelve { detail: string | object[] } en los errores. */
async function errorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown }
    if (typeof body.detail === 'string') return body.detail
  } catch {
    // cuerpo vacío o no JSON: se usa el mensaje genérico
  }
  if (response.status === 401) return 'Tu sesión venció. Volvé a iniciar sesión.'
  if (response.status === 404) return 'No encontramos lo que buscabas.'
  return `La API respondió con un error (${response.status}).`
}

export const api = {
  health: () => request<{ status: string }>('/health'),

  listRepositories: () => request<Repository[]>('/repositories'),

  connectRepository: (url: string) =>
    request<Repository>('/repositories', { method: 'POST', body: JSON.stringify({ url }) }),

  repositoryHistory: (repositoryId: string) =>
    request<Scan[]>(`/repositories/${encodeURIComponent(repositoryId)}/history`),

  startScan: (repositoryId: string) =>
    request<Scan>(`/repositories/${encodeURIComponent(repositoryId)}/scans`, { method: 'POST' }),

  getScan: (scanId: string) => request<Scan>(`/scans/${encodeURIComponent(scanId)}`),

  getScanFindings: (scanId: string) =>
    request<FindingRecord[]>(`/scans/${encodeURIComponent(scanId)}/findings`),

  /** URLs firmadas que vencen: pedirlas justo antes de descargar. */
  getScanReport: (scanId: string) => request<ScanReport>(`/scans/${encodeURIComponent(scanId)}/report`),

  updateFinding: (findingId: string, status: FindingStatus) =>
    request<FindingRecord>(`/findings/${encodeURIComponent(findingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
}
