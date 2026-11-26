# Qubitor

Plataforma de **auditoría continua de seguridad**. Conectás un repositorio de GitHub y Qubitor lo analiza con cinco motores (código inseguro, dependencias vulnerables, secretos expuestos, criptografía vulnerable —también frente a computadoras cuánticas— y configuración de infraestructura), prioriza los hallazgos con IA y devuelve un reporte con una hoja de ruta de remediación.

**App publicada:** https://qubitor.scanner-app.workers.dev

> Trabajo Práctico Integrador — *Desarrollo de Software Cloud*, UTN Facultad Regional La Plata, 2026.

## Equipo

| Integrante | Legajo | Módulo |
|---|---|---|
| Wilt, Juan Ignacio | 33151 | A — API, base de datos, orquestador, cola de escaneos e historial |
| Balda, Matías | 33460 | B — Base del frontend, dashboard, deploy y CI |
| Marini, Alvaro | 33133 | C — Criptografía clásica, secretos, SAST y contenedor de escaneo |
| Pértile de la Vega, Valentina | 33288 | D — Criptografía post-cuántica, dependencias (SCA), reportes y caché |
| Chiappini, Valentino | 33072 | E — Integración con GitHub, triage con IA y webhook |

## Cómo funciona un escaneo
 
```
POST /repositories/{id}/scans  →  cola (Redis)  →  scan-worker
   │
   ▼
[1] Clonado      git clone --depth 1 en un directorio temporal (límite 50 MB)
[2] Motores      SAST │ SCA │ Secretos │ Criptografía │ Configuración, en paralelo
[3] Normalizar   severidad unificada y deduplicación por fingerprint
[4] Triage IA    Gemini: posible falso positivo (sugerencia), severidad (±1 nivel) y remediación
[5] Risk Score   puntaje 0–100 y nota A–F
[6] Guardar      hallazgos en Postgres, reporte JSON/PDF y CBOM en el bucket
   │
   ▼
Se borra el clon: Qubitor no conserva el código de los usuarios.
```

El frontend consulta el progreso por etapa mientras el escaneo corre. Si un motor falla, los demás siguen y el escaneo queda parcial.

## Arquitectura

```
                         ┌──────────────────────────┐
  Navegador ───────────► │ Cloudflare Workers       │  frontend React (archivos estáticos)
                         └────────────┬─────────────┘
                                      │ HTTPS + JWT de Clerk
                                      ▼
  GitHub ── push ──► Worker de   ┌──────────────────┐        ┌────────────────────────┐
                     webhooks ──►│ Render: API      │ ─────► │ Supabase: Postgres     │
                     (HMAC)      │ FastAPI          │        │ (RLS: ver ARCHITECTURE)│
                                 └────────┬─────────┘        └────────────────────────┘
                                          │ encola                        ▲
                                          ▼                               │
                                 ┌──────────────────┐                     │
                                 │ Upstash Redis    │                     │
                                 │ (cola, RQ)       │                     │
                                 └────────┬─────────┘                     │
                                          ▼                               │
                                 ┌──────────────────┐  guarda hallazgos   │
                                 │ Render: worker   │ ────────────────────┘
                                 │ (Docker sin root)│
                                 └──┬────┬─────┬────┘
                                    │    │     │
                     Gemini API ◄───┘    │     └───► Bucket S3-compatible: reportes y CBOM
                     (triage)            ▼            (URLs firmadas de 10 min)
                                 Cloudflare KV: caché de OSV (24 h)

  Worker keep-alive (cron 10 min) ── GET /health ──► API ◄── GET /health ── Better Stack (uptime)
```

### Componentes cloud

Cada módulo tiene un componente cloud propio. La materia presenta los servicios de AWS; el proyecto usa sus equivalentes con capa gratuita.

| Módulo | Componente | Servicio | Equivalente en AWS |
|---|---|---|---|
| A | Cola de escaneos y separación API / worker | Upstash Redis + RQ, dos servicios en Render | SQS + ECS |
| B | Deploy, CI y observabilidad | Render, Cloudflare Workers, GitHub Actions, Better Stack | CloudFormation + CloudWatch |
| C | Contenedor de escaneo | Docker en Render (usuario sin privilegios; ver los límites en docs/ARCHITECTURE.md, «Seguridad») | ECS / Fargate |
| D | Reportes en bucket y caché NoSQL | Bucket S3-compatible (Supabase Storage o Cloudflare R2) y Cloudflare KV | S3 + DynamoDB |
| E | Webhook serverless e IA gestionada | Cloudflare Worker y Gemini API | Lambda + API Gateway y Bedrock |

## Motores de análisis

Todos implementan el mismo contrato (`backend/app/engines/base.py`): reciben la ruta del repo y devuelven una lista de `Finding`.

| Motor | Qué detecta | Cómo |
|---|---|---|
| **SAST** | Código inseguro: inyección, `eval`, deserialización, etc. | Bandit (Python) y Semgrep con reglas propias (JavaScript/TypeScript) |
| **Secretos** | Claves y tokens expuestos (AWS, GitHub, Google, Slack, claves privadas) | Patrones conocidos y entropía de Shannon; el valor siempre se enmascara |
| **Criptografía clásica** | MD5/SHA-1, DES/RC4, RSA < 2048, AES-ECB, TLS sin validar, random inseguro | `ast` en Python y expresiones regulares en JavaScript |
| **Criptografía post-cuántica** | RSA, ECDSA, ECDH, DH, EdDSA (Shor) y AES-128 (Grover); certificados, claves y keystores | `ast`, regex y la librería `cryptography`; arma el inventario criptográfico (CBOM) |
| **SCA** | Dependencias con vulnerabilidades conocidas (CVE, CVSS, versión corregida) | `requirements.txt`, `package.json` y `package-lock.json` contra la API de OSV (solo versiones exactas; todavía no lee `pyproject.toml`, `poetry.lock`, `yarn.lock` ni `pnpm-lock.yaml`) |
| **Configuración** | Dockerfile con root, docker-compose, nginx con TLS inseguro, Terraform abierto a Internet | Reglas propias; sus hallazgos se muestran dentro de SAST |

Severidades: `critical`, `high`, `medium`, `low` e `info` (inventario sin riesgo). El Risk Score parte de 100 y resta un peso por hallazgo abierto: 10, 5, 2, 0,5 y 0. Un falso positivo sugerido por la IA **sigue contando** hasta que una persona lo marca; las marcas de falso positivo se conservan en los escaneos siguientes.

El repo analizado no puede silenciar hallazgos: se ignoran `.bandit`, `# nosec`, `.semgrepignore` y `// nosemgrep`. Los archivos que no son UTF-8 se analizan igual (latin-1). Si el historial de Git supera los límites (50 MB, 8 MB de cambios o 15 s), se informa con un hallazgo `info` en lugar de darlo por limpio.

## Funcionalidades

- Login con GitHub (Clerk) y conexión de repos públicos; los privados se habilitan con `GITHUB_PRIVATE_REPOS=true`.
- Escaneo manual, o automático en cada push con el Worker de webhooks. **Estado:** el código está probado de punta a punta en local, pero el Worker todavía no está desplegado en Cloudflare (ver `infra/webhook-worker/README.md`). Solo acepta los repos de `ALLOWED_REPOSITORIES`.
- Dashboard con Risk Score, hallazgos por motor y severidad, y resumen ejecutivo generado con IA.
- Panel de remediación por hallazgo: explicación, pasos y posible falso positivo (solo sugerencia: no cambia el Risk Score).
- Vistas por motor: código inseguro, secretos, dependencias (con el comando para actualizar) y preparación post-cuántica (CBOM, exposición a Shor, hoja de ruta a ML-KEM / ML-DSA y urgencia según la desigualdad de Mosca).
- Historial de escaneos con la evolución del Risk Score y los hallazgos nuevos y resueltos.
- Descarga del reporte en PDF y del CBOM en CycloneDX 1.6.

## Estructura del repositorio

```
qubitor/
├── backend/
│   ├── app/
│   │   ├── api/            # endpoints REST y autenticación con Clerk
│   │   ├── models/         # modelos SQLAlchemy (migraciones en backend/alembic)
│   │   ├── orchestrator/   # motores en paralelo, normalización y Risk Score
│   │   ├── worker/         # cola, scan-worker, clonado y guardado
│   │   ├── engines/        # base.py (contrato) y los motores sast, sca, secrets y crypto
│   │   ├── ai/             # triage y resumen ejecutivo con Gemini
│   │   ├── integrations/   # GitHub
│   │   └── storage/        # reportes, PDF y CBOM en el bucket
│   ├── worker/Dockerfile   # imagen del scan-worker
│   └── tests/
├── frontend/src/
│   ├── components/  lib/  types/   # base compartida
│   └── features/                    # una carpeta por vista
├── infra/
│   ├── webhook-worker/     # Cloudflare Worker que recibe los webhooks de GitHub
│   └── worker-keepalive/   # Cloudflare Worker que mantiene despierta la API
├── docs/                   # arquitectura, contribución, equipo y AI-DECISIONS
└── .github/workflows/ci.yml
```

## Correr en local

Requisitos: Python 3.11+, Node 20+, y Docker si querés levantar Postgres y Redis en local.

### Backend (API)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env        # completar; cada variable está explicada ahí
alembic upgrade head        # crea las tablas en la base de DATABASE_URL
uvicorn app.main:app --reload
```

La API queda en `http://localhost:8000` (`/health` para comprobarlo).

### Scan-worker

Toma los escaneos de la cola. Necesita la misma `REDIS_URL` que la API:

```bash
cd backend && source .venv/bin/activate
python -m app.worker.run
```

### Frontend

```bash
cd frontend
npm install
cp .env.example .env        # sin VITE_API_URL usa datos de ejemplo; sin la clave de Clerk, entra sin login
npm run dev
```

El frontend queda en `http://localhost:5173`.

### Tests

```bash
cd backend && pytest -q           # backend
cd frontend && npm test           # frontend
```

Algunos tests usan servicios reales y se activan solo si se piden:

| Variable | Qué habilita |
|---|---|
| `QUBITOR_TEST_DATABASE_URL` | Tests de la API y del guardado contra un Postgres (por ejemplo, uno en Docker) |
| `QUBITOR_TESTS_RED=1` | Tests con internet: OSV real, esquema de CycloneDX y el repo de demo |
| `QUBITOR_TESTS_BUCKET=1` | Test contra el bucket real configurado en `backend/.env` |

## Deploy

| Pieza | Dónde | Cómo |
|---|---|---|
| Frontend | Cloudflare Workers (archivos estáticos) | Build desde `frontend/` con `npm run build` y `npx wrangler deploy`, que toma la configuración de `frontend/wrangler.jsonc` (incluido el modo SPA, necesario para que funcione la vuelta del login). `VITE_API_URL` y `VITE_CLERK_PUBLISHABLE_KEY` son variables de build: si cambian, hay que volver a construir. |
| API | Render | `uvicorn app.main:app`. `CORS_ORIGINS` tiene que incluir la URL del frontend. |
| Scan-worker | Render, con `backend/worker/Dockerfile` | `python -m app.worker.run` |
| Base de datos | Supabase | Usar el **session pooler** (Render no sale por IPv6, que es lo único que acepta la conexión directa) con el formato `postgresql+psycopg://…?sslmode=require`. Las tablas se crean con `alembic upgrade head`. |
| Webhook y keep-alive | Cloudflare Workers | Ver `infra/webhook-worker` e `infra/worker-keepalive` |

Las variables de cada servicio están documentadas en `backend/.env.example` y `frontend/.env.example`. Ningún secreto va en el repo.

Los servicios de Render están definidos como código en [`render.yaml`](render.yaml), con dos entornos: **staging** despliega desde `develop` y **producción** desde `main` cuando la CI pasa. Cómo funcionan y qué secretos cargar en el panel: [docs/deploy.md](docs/deploy.md).

## CI

GitHub Actions (`.github/workflows/ci.yml`) corre en cada pull request y en cada push a `main` y `develop`:

- frontend: lint, tests (vitest) y build;
- backend: `pytest` con un Postgres 16 (autorización, aislamiento, webhooks y guardado) y las migraciones de Alembic (subir, bajar, subir y `alembic check`);
- Webhook Worker: tests, tipos y `wrangler deploy --dry-run`;
- scan-worker: build de la imagen Docker y tests de los motores dentro de ella (Semgrep real, 512 MB);
- en los PRs, auditoría de dependencias (`pip-audit` y `npm audit --omit=dev`).

## Repo de demo

[`qubitor-demo-vulnerable`](https://github.com/ValentinaPertile/qubitor-demo-vulnerable) tiene vulnerabilidades plantadas a propósito (dependencias con CVE, criptografía débil y vulnerable a Shor, un certificado RSA-1024 con SHA-1, secretos falsos y código inseguro). Es el repo que se escanea en la demo y en los tests de integración. Las credenciales que contiene son inventadas.

## Documentación

- [Arquitectura](docs/ARCHITECTURE.md)
- [Cómo contribuir](docs/CONTRIBUTING.md): ramas, Conventional Commits y revisión cruzada de PRs
- [Equipo](docs/TEAM_CHART.md)
- [AI-DECISIONS](docs/AI-DECISIONS.md): registro de todo el código generado con IA y de su revisión humana
- [Producto](PRODUCT.md) y [diseño](DESIGN.md)

## Cronograma

| Hito | Fecha | Entregable |
|---|---|---|
| One-Pager | 24/08/2026 | Problema, solución y modelo de negocio |
| Checkpoint 1 | 28/09/2026 | Arquitectura, diagrama cloud y repo inicial |
| Checkpoint 2 | 09/11/2026 | Demo funcional desplegada |
| Defensa final | 30/11/2026 | Presentación en vivo |
