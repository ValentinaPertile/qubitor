import type { FindingRecord, Severity } from '@/types/Finding'

/**
 * Clasifica los hallazgos de criptografía según la amenaza cuántica y arma la
 * hoja de ruta de migración. Toma las reglas de pqc.py y también las de
 * classic.py: RSA < 2048 lo reporta classic.py, pero también lo rompe Shor.
 */

/** shor: lo rompe una computadora cuántica · grover: le reduce la seguridad
 *  · broken: ya está roto hoy, sin computadora cuántica · none: sin riesgo conocido. */
export type Threat = 'shor' | 'grover' | 'broken' | 'none'

/** Para qué se usa un algoritmo asimétrico: define a qué estándar migrar. */
type AsymmetricUse = 'exchange' | 'signature' | 'both'

export interface CryptoUsage {
  finding: FindingRecord
  algorithm: string
  threat: Threat
  location: string
  /** No resuelto ni descartado. Los de inventario siempre cuentan. */
  active: boolean
}

export interface ExposureSummary {
  total: number
  byThreat: Record<Threat, number>
  /** Porcentaje del uso criptográfico vulnerable a Shor (0 a 100). */
  shorPercent: number
}

export interface MigrationStep {
  id: string
  title: string
  /** Hacia dónde migrar. */
  target: string
  why: string
  priority: Severity
  usages: CryptoUsage[]
}

export const THREATS: readonly Threat[] = ['shor', 'grover', 'broken', 'none']

export const THREAT_LABEL: Record<Threat, string> = {
  shor: 'Shor',
  grover: 'Grover',
  broken: 'Rota hoy',
  none: 'Sin riesgo conocido',
}

/** Severidad que tienen los hallazgos de cada amenaza: da el color de su barra. */
export const THREAT_SEVERITY: Record<Threat, Severity> = {
  shor: 'medium',
  grover: 'low',
  broken: 'high',
  none: 'info',
}

const SHOR_RULES: Record<string, { algorithm: string; use: AsymmetricUse }> = {
  'crypto.pqc.rsa-keygen': { algorithm: 'RSA', use: 'both' },
  'crypto.pqc.ec-keygen': { algorithm: 'ECC', use: 'both' },
  'crypto.pqc.ecdsa': { algorithm: 'ECDSA', use: 'signature' },
  'crypto.pqc.eddsa': { algorithm: 'EdDSA', use: 'signature' },
  'crypto.pqc.ecdh': { algorithm: 'ECDH', use: 'exchange' },
  'crypto.pqc.dh': { algorithm: 'DH', use: 'exchange' },
  'crypto.pqc.dsa-keygen': { algorithm: 'DSA', use: 'signature' },
  'crypto.classic.rsa-weak-key': { algorithm: 'RSA < 2048', use: 'both' },
  // Certificados y claves versionados (certs.py): un certificado sirve para firmar.
  'crypto.pqc.cert-quantum-vulnerable': { algorithm: 'Certificado', use: 'signature' },
  'crypto.pqc.cert-weak-key': { algorithm: 'RSA < 2048', use: 'both' },
}

/** RSA de menos de 2048 bits, en el código (classic.py) o en un certificado (certs.py). */
const WEAK_RSA_RULES = new Set(['crypto.classic.rsa-weak-key', 'crypto.pqc.cert-weak-key'])

const BROKEN_ALGORITHMS: Record<string, string> = {
  'crypto.classic.weak-hash': 'MD5 / SHA-1',
  'crypto.classic.weak-cipher': 'DES / 3DES / RC4 / Blowfish',
  'crypto.classic.aes-ecb': 'AES-ECB',
  'crypto.classic.tls-insecure': 'TLS sin validar',
  'crypto.classic.insecure-random': 'Random no criptográfico',
}

const THREAT_ORDER: Record<Threat, number> = { broken: 0, shor: 1, grover: 2, none: 3 }

/** Cada hallazgo del motor de criptografía, clasificado. Los falsos positivos quedan afuera. */
export function cryptoUsages(findings: readonly FindingRecord[]): CryptoUsage[] {
  return findings
    .filter((f) => f.engine === 'crypto' && !f.triage?.is_false_positive)
    .map(toUsage)
    .sort(
      (a, b) =>
        THREAT_ORDER[a.threat] - THREAT_ORDER[b.threat] ||
        a.finding.file_path.localeCompare(b.finding.file_path) ||
        (a.finding.line ?? 0) - (b.finding.line ?? 0),
    )
}

export function exposure(usages: readonly CryptoUsage[]): ExposureSummary {
  const byThreat: Record<Threat, number> = { shor: 0, grover: 0, broken: 0, none: 0 }
  const active = usages.filter((u) => u.active)
  for (const usage of active) byThreat[usage.threat] += 1
  return {
    total: active.length,
    byThreat,
    shorPercent: active.length === 0 ? 0 : Math.round((byThreat.shor / active.length) * 100),
  }
}

/**
 * Pasos de migración, de lo más urgente a lo menos. El intercambio de claves va
 * antes que las firmas: lo cifrado hoy se puede guardar y descifrar después,
 * mientras que una firma recién se puede falsificar cuando exista la máquina.
 */
export function migrationRoadmap(usages: readonly CryptoUsage[]): MigrationStep[] {
  const active = usages.filter((u) => u.active)
  const withUse = (use: AsymmetricUse) =>
    active.filter((u) => !WEAK_RSA_RULES.has(u.finding.rule_id) && SHOR_RULES[u.finding.rule_id]?.use === use)

  const steps: MigrationStep[] = [
    {
      id: 'weak-rsa',
      title: 'Reemplazar las claves RSA de menos de 2048 bits',
      target: 'RSA de 3072 bits ya, y después ML-KEM o ML-DSA',
      why: 'Se pueden factorizar hoy con recursos clásicos, sin esperar a una computadora cuántica.',
      priority: 'high',
      usages: active.filter((u) => WEAK_RSA_RULES.has(u.finding.rule_id)),
    },
    {
      id: 'exchange',
      title: 'Migrar el intercambio de claves a ML-KEM',
      target: 'ML-KEM (FIPS 203)',
      why: 'Es lo más urgente: un atacante puede guardar hoy el tráfico cifrado y descifrarlo cuando exista la computadora cuántica («cosechar ahora, descifrar después»). Mientras tanto, conviene un esquema híbrido, como X25519 + ML-KEM-768.',
      priority: 'medium',
      usages: withUse('exchange'),
    },
    {
      id: 'asymmetric-keys',
      title: 'Definir el uso de las claves RSA y de curva elíptica',
      target: 'ML-KEM si cifran o acuerdan claves · ML-DSA (FIPS 204) si firman',
      why: 'La misma clave puede servir para cifrar o para firmar, y cada uso migra a un estándar distinto.',
      priority: 'medium',
      usages: withUse('both'),
    },
    {
      id: 'signature',
      title: 'Migrar las firmas a ML-DSA',
      target: 'ML-DSA (FIPS 204)',
      why: 'Una firma recién se puede falsificar cuando exista la computadora cuántica, pero las de larga vida (certificados raíz, firmware) conviene migrarlas antes.',
      priority: 'medium',
      usages: withUse('signature'),
    },
    {
      id: 'aes-128',
      title: 'Pasar de AES-128 a AES-256',
      target: 'AES-256',
      why: 'Grover reduce la seguridad efectiva de AES-128 a la mitad. Importa en datos que tienen que seguir siendo secretos por muchos años.',
      priority: 'low',
      usages: active.filter((u) => u.threat === 'grover'),
    },
  ]
  return steps.filter((step) => step.usages.length > 0)
}

function toUsage(finding: FindingRecord): CryptoUsage {
  const location = finding.line != null ? `${finding.file_path}:${finding.line}` : finding.file_path
  const informational = finding.severity === 'info'
  const active = informational || finding.status === 'open'
  return { finding, location, active, ...classify(finding) }
}

function classify(finding: FindingRecord): { algorithm: string; threat: Threat } {
  if (finding.rule_id.startsWith('crypto.pqc.cert-')) return classifyCert(finding)
  const shor = SHOR_RULES[finding.rule_id]
  if (shor) return { algorithm: shor.algorithm, threat: 'shor' }
  if (finding.rule_id === 'crypto.pqc.aes-128') return { algorithm: 'AES-128', threat: 'grover' }
  // Lo demás de classic.py ya es débil hoy, aunque se sume una regla nueva.
  if (finding.rule_id.startsWith('crypto.classic.')) {
    return { algorithm: BROKEN_ALGORITHMS[finding.rule_id] ?? finding.title, threat: 'broken' }
  }
  const algorithm = finding.metadata.algorithm
  return { algorithm: typeof algorithm === 'string' ? algorithm : finding.title, threat: 'none' }
}

const CERT_NOUN: Record<string, string> = {
  certificate: 'Certificado',
  private_key: 'Clave privada',
  public_key: 'Clave pública',
}

/** Certificados y claves: el nombre dice qué es y con qué algoritmo, p. ej. «Certificado RSA-1024». */
function classifyCert(finding: FindingRecord): { algorithm: string; threat: Threat } {
  const { kind, algorithm, key_size: bits, signature_hash: hash } = finding.metadata
  const noun = (typeof kind === 'string' && CERT_NOUN[kind]) || 'Certificado'
  const key = typeof algorithm === 'string' ? algorithm : ''
  const size = typeof bits === 'number' && (key === 'RSA' || key === 'DSA') ? `-${bits}` : ''
  const label = `${noun} ${key}${size}`.trim()

  if (finding.rule_id === 'crypto.pqc.cert-weak-signature') {
    const name = typeof hash === 'string' ? hash.toUpperCase().replace('SHA1', 'SHA-1') : 'débil'
    return { algorithm: `${label} con firma ${name}`, threat: 'broken' }
  }
  if (finding.rule_id === 'crypto.pqc.cert-expired') return { algorithm: `${label} vencido`, threat: 'broken' }
  if (finding.rule_id === 'crypto.pqc.cert-expiring') return { algorithm: `${label} por vencer`, threat: 'none' }
  return { algorithm: label, threat: SHOR_RULES[finding.rule_id] ? 'shor' : 'none' }
}
