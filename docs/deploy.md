# Deploy en Render: staging y producción

La infraestructura de Render está definida como código en [`render.yaml`](../render.yaml) (Blueprint de Render). Define un proyecto, `qubitor`, con dos entornos separados.

| Entorno | Rama | Servicios en Render | Cuándo despliega |
|---|---|---|---|
| `staging` | `develop` | `qubitor-api-staging`, `qubitor-scan-worker-staging` | Cuando la CI pasa en verde para un commit de `develop`. |
| `production` | `main` | `qubitor-api`, `qubitor-scan-worker` | Cuando la CI pasa en verde para un commit de `main`. |

Flujo: `feature/*` → PR a `develop` → se prueba en staging → PR de `develop` a `main` → producción. Cómo abrir y mergear cada PR (incluida la estrategia de merge): [CONTRIBUTING.md](CONTRIBUTING.md#3-pull-requests).

## Cuándo despliega Render

Render está conectado directo a este repo mediante la app de Render en GitHub. Cada servicio tiene el auto-deploy en **After CI Checks Pass** (`autoDeployTrigger: checksPass` en `render.yaml`):

```
merge en develop / main ──▶ CI (GitHub Actions) en verde ──▶ Render despliega
```

- La CI corre en cada push a `main` y a `develop` (`.github/workflows/ci.yml`). Render espera a que terminen los jobs de ese commit y solo despliega si pasaron todos.
- Si la CI queda en rojo, Render no despliega y el entorno sigue con la versión anterior. Se arregla con otro PR; no hace falta tocar Render.
- Para desplegar sin esperar, o volver a intentar: Render → servicio → **Manual Deploy** → *Deploy latest commit*.

## Qué está en Render y qué no

- **En `render.yaml`:** la API (Python, `uvicorn app.main:app`) y el scan-worker (Docker, `backend/worker/Dockerfile`) de cada entorno, con su health check en `/health`. El scan-worker es un Web Service y no un Background Worker porque los workers de Render no tienen plan free.
- **Fuera de Render, uno por entorno:** la base (un proyecto de Supabase por entorno), la cola (una base de Upstash Redis por entorno) y el bucket de reportes. Staging nunca apunta a los de producción. La caché de OSV en Cloudflare KV se puede compartir porque guarda datos públicos.
- **En Cloudflare (no cambia):** el frontend, el webhook-worker y el keep-alive apuntan a producción. Staging no tiene frontend propio: se prueba con el frontend local (`VITE_API_URL` = URL de `qubitor-api-staging`), por eso su `CORS_ORIGINS` es `http://localhost:5173`. Staging no tiene keep-alive y se duerme tras 15 minutos sin tráfico.

## Plan y región

Todo en plan `free` y región `oregon`. Los cuatro Web Services comparten las 750 h/mes del workspace: el keep-alive mantiene despierta solo producción y staging duerme cuando no se usa. La región no se puede cambiar después de crear un servicio.

## Crear o sincronizar el Blueprint

1. Render → **New → Blueprint** → elegir este repo (rama `main`).
2. Revisar que los nombres de producción (`qubitor-api` y `qubitor-scan-worker`) coincidan con los servicios que ya existen. Si no coinciden, Render crea servicios nuevos con otra URL y hay que actualizar `VITE_API_URL` del frontend, `TARGETS` del keep-alive y `QUBITOR_API_URL` del webhook-worker.
3. Cargar los secretos que pide el panel (lista abajo).
4. Correr las migraciones contra la base de cada entorno: `alembic upgrade head` con el `DATABASE_URL` de ese entorno. El `preDeployCommand` de Render solo existe en planes pagos.

Render pide los valores `sync: false` **solo al crear el Blueprint**. Si después se agrega una variable así a `render.yaml`, hay que cargarla a mano en cada servicio.

## Secretos para cargar a mano en el panel

Cada entorno lleva sus propios valores. Qué es cada variable está explicado en [`backend/.env.example`](../backend/.env.example).

| Variable | API | Scan-worker | Notas |
|---|:-:|:-:|---|
| `DATABASE_URL` | ✓ | ✓ | Session pooler de Supabase del entorno, `postgresql+psycopg://…?sslmode=require`. |
| `REDIS_URL` | ✓ | ✓ | Upstash del entorno (`rediss://…`). Tiene que ser la misma en la API y el worker del mismo entorno. |
| `CLERK_ISSUER` | ✓ | | Instancia de Clerk del entorno (no es secreto, pero cambia por entorno). |
| `CLERK_SECRET_KEY` | ✓ | | |
| `INTERNAL_WEBHOOK_SECRET` | ✓ (solo producción) | | El mismo valor que el secreto del webhook-worker de Cloudflare. En staging lo genera Render. |
| `R2_ENDPOINT`, `R2_REGION` | ✓ | ✓ | Endpoint S3 y región de Supabase Storage. |
| `R2_BUCKET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | ✓ | ✓ | Bucket del entorno y sus credenciales. |
| `CF_ACCOUNT_ID`, `CF_KV_NAMESPACE_ID`, `CF_API_TOKEN` | | ✓ | Caché de OSV en Cloudflare KV. |
| `GEMINI_API_KEY` | | ✓ | Triage con IA. |

La configuración no secreta (`PYTHON_VERSION`, `CORS_ORIGINS`, `AUTH_DISABLED`, `GITHUB_PRIVATE_REPOS`, `SEMGREP_ENABLED`) está en los grupos `qubitor-staging-config` y `qubitor-production-config` de `render.yaml`.
