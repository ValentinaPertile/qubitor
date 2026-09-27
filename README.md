# Qubitor

Plataforma SaaS de **auditoría continua de seguridad** con evaluación de hallazgos asistida por IA. Conectá un repositorio de GitHub/GitLab y Qubitor ejecuta SAST, SCA, detección de secretos y auditoría de criptografía vulnerable, prioriza los resultados con IA y devuelve un reporte accionable con hoja de ruta de remediación.

> Trabajo Práctico Integrador — *Desarrollo de Software Cloud*, UTN Facultad Regional La Plata (2026)

## Equipo

| Integrante | Legajo |
|---|---|
| Balda, Matías | 33460 |
| Pértile de la Vega, Valentina | 33288 |
| Wilt, Juan Ignacio | 33151 |
| Marini, Alvaro | 33133 |
| Chiappini, Valentino | 33072 |

## Arquitectura

Tres capas desacopladas sobre servicios administrados, sin servidores propios que mantener:

```
┌────────────────────┐   HTTPS/JSON   ┌────────────────────┐   SQL   ┌───────────────────────┐
│  Cloudflare Pages   │ ─────────────► │    Render (API)     │ ──────► │  Supabase (Postgres)  │
│  Frontend (React)   │ ◄───────────── │   FastAPI backend    │         │  + Row Level Security │
└────────────────────┘                 └──────────┬──────────┘         └───────────────────────┘
                                                    │
                          ┌─────────────────────────┼─────────────────────────┐
                          ▼                         ▼                         ▼
                    Gemini API           GitHub / GitLab API           Clerk / Auth0
              (evaluación de hallazgos)     (repos del usuario)        (autenticación)

Cloudflare Worker (Cron 10 min) ── GET /health ──► Render   (keep-alive)
Better Stack                    ── logs / uptime ► Render   (observabilidad)
```

Ver el detalle completo (justificación de cada componente, flujo end-to-end, modelo de datos, diseño de API, seguridad, costos y riesgos) en el documento de arquitectura del Checkpoint 1.

## Stack

| Capa | Tecnología | Por qué |
|---|---|---|
| Frontend | React + [Cloudflare Pages](https://pages.cloudflare.com/) | Hosting estático + CDN global, deploy continuo desde Git, capa gratuita generosa |
| Backend / API | FastAPI en [Render](https://render.com/) | Deploy continuo desde GitHub, variables de entorno nativas, `render.yaml` reproducible |
| Base de datos | [Supabase](https://supabase.com/) (Postgres) | Postgres administrado, Row Level Security por organización, backups automáticos |
| IA | [Gemini API](https://ai.google.dev/) | Clasifica hallazgos, descarta falsos positivos, redacta remediación en lenguaje natural |
| Autenticación | Clerk / Auth0 | Identity provider gestionado, OAuth con GitHub/GitLab, JWT |
| Observabilidad | Better Stack + Cloudflare Worker (keep-alive) | Logs centralizados, uptime, evita cold start del plan free de Render |

## Estructura del repositorio

```
qubitor/
├── backend/          # API FastAPI (motores de escaneo, orquestación, integraciones)
├── frontend/          # SPA React (dashboard, conexión de repos, reporte de hallazgos)
├── AI-DECISIONS.md    # Log de auditoría de decisiones asistidas por IA (obligatorio)
├── CONTRIBUTING.md    # Flujo de ramas, commits, PRs, Kanban
└── README.md
```

## Setup local

### Requisitos

- Python 3.11+
- Node 20+
- Cuenta de Supabase, Gemini API y Clerk/Auth0 (variables de entorno)

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # completar DATABASE_URL, GEMINI_API_KEY, claves de auth
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
cp .env.example .env   # completar VITE_API_URL, claves públicas de auth
npm run dev
```

La API queda disponible en `http://localhost:8000` y el frontend en `http://localhost:5173` (o el puerto que indique Vite).

## Flujo de escaneo

1. **Conexión** — el usuario se autentica y autoriza a Qubitor vía OAuth de GitHub/GitLab.
2. **Disparo** — manual desde el frontend o automático por webhook en cada push.
3. **Ejecución** — el backend corre en paralelo los cuatro motores: SAST, SCA (contra OSV/NVD), secret scanning y auditoría de criptografía vulnerable.
4. **Agregación** — cada motor persiste sus hallazgos crudos con severidad y categoría.
5. **Evaluación con IA** — Gemini descarta falsos positivos, re-prioriza por severidad real y redacta sugerencias de remediación.
6. **Reporte** — el frontend renderiza el dashboard con el reporte priorizado.

## Entornos

| Entorno | Rama | Destino |
|---|---|---|
| Desarrollo local | `feature/*` | Backend y frontend corridos localmente |
| Staging (opcional) | `develop` | Deploy de prueba en Render / Cloudflare Pages |
| Producción | `main` | Deploy automático tras cada PR aprobado |

## CI/CD

GitHub Actions corre en cada Pull Request: lint + type-check del frontend, lint + tests (`pytest`) del backend, y build de verificación. El deploy real lo gestionan Render y Cloudflare Pages automáticamente al detectar push a `main`.

## Contribuir

Ver [`CONTRIBUTING.md`](./CONTRIBUTING.md) para el flujo de ramas, convención de commits, proceso de PR y gestión del Kanban.

Todo código o diseño generado con asistencia de IA debe quedar registrado en [`AI-DECISIONS.md`](./AI-DECISIONS.md) antes de mergear.

## Cronograma del TPI

| Hito | Fecha | Entregable |
|---|---|---|
| Clase 1 | 24/08/2026 | One-Pager |
| Checkpoint 1 | 28/09/2026 | Definición de arquitectura, diagrama cloud, repo inicial con actividad |
| Checkpoint 2 | 09/11/2026 | Demo funcional (infraestructura desplegada, backend operativo) |
| Defensa Final | 30/11/2026 | Presentación en vivo del MVP en producción |
