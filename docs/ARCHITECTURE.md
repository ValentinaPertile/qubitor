# Arquitectura — Qubitor

> Trabajo Práctico Integrador — Desarrollo de Software Cloud, UTN FRLP (2026)
> Versión final (defensa del 30/11/2026). Reemplaza a la del Checkpoint 1 (28/09/2026).

## 1. Alcance del documento

Este documento describe la arquitectura técnica y la infraestructura cloud de Qubitor tal como está desplegada para la defensa final: componentes, servicios por componente, flujo de un escaneo, API, modelo de datos, seguridad, despliegue, costos, riesgos y las decisiones de diseño principales.

### Qué cambió desde el Checkpoint 1

| Checkpoint 1 | Versión final | Por qué |
|---|---|---|
| Una sola API que escanea en una tarea en segundo plano (`BackgroundTasks`) | API y **scan-worker** separados, comunicados por una **cola** (Upstash Redis + RQ) | Un escaneo tarda hasta minutos: en la API bloqueaba memoria y se perdía si Render reiniciaba el servicio. La cola da reintentos y una cola de errores. |
| Los motores corren en el mismo proceso que la API | El worker corre en un **contenedor Docker aislado**, con usuario sin privilegios | Qubitor ejecuta herramientas sobre código ajeno que no es de confianza. |
| Todo se guarda en Postgres | Reportes (PDF, JSON) y CBOM en un **bucket S3-compatible** (Cloudflare R2); caché de OSV en **Cloudflare KV** | Los archivos no son datos relacionales, y la caché es clave-valor con vencimiento. |
| Escaneo por webhook «a futuro» | **Cloudflare Worker** que recibe los webhooks de GitHub y dispara el escaneo en cada push | Recibir webhooks no requiere un servidor encendido todo el día. |
| Un usuario pertenece a una organización y no hay roles | **Organizaciones con varios miembros** y roles admin / member tomados de Clerk | Pedido de la versión final del plan. |
| Frontend en Cloudflare Pages | Frontend como archivos estáticos en **Cloudflare Workers** | Mismo CDN y capa gratuita; un solo producto para el frontend y los Workers. |

## 2. Arquitectura general

```
                         ┌──────────────────────────┐
  Navegador ───────────► │ Cloudflare Workers       │  frontend React (archivos estáticos)
                         └────────────┬─────────────┘
                                      │ HTTPS + JWT de Clerk
                                      ▼
  GitHub ── push ──► Worker de   ┌──────────────────┐        ┌────────────────────────┐
                     webhooks ──►│ Render: API      │ ─────► │ Supabase: Postgres     │
                     (HMAC)      │ FastAPI          │        │ con Row Level Security │
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
                                 │ (Docker aislado) │
                                 └──┬────┬─────┬────┘
                                    │    │     │
                     Gemini API ◄───┘    │     └───► Cloudflare R2: reportes y CBOM
                     (triage)            ▼            (URLs firmadas de 10 min)
                                 Cloudflare KV: caché de OSV (24 h)

  Worker keep-alive (cron 10 min) ── GET /health ──► API ◄── GET /health ── Better Stack (uptime)
  Clerk: login con GitHub, organizaciones y roles (el frontend lo usa; la API valida sus JWT)
```

### Responsabilidad de cada pieza

- **Frontend:** SPA en React + Vite + TypeScript. Solo habla con la API y con Clerk; no tiene credenciales de otros servicios ni lógica de negocio sensible.
- **API (FastAPI en Render):** valida el JWT de Clerk, aplica los roles, expone los datos y **encola** los escaneos. Responde enseguida: nunca escanea.
- **Cola (Upstash Redis + RQ):** desacopla la API del worker. Si el worker está ocupado o reiniciando, los escaneos esperan en la cola en lugar de perderse.
- **Scan-worker (Docker en Render):** clona el repo, corre los motores, hace el triage con IA, calcula el Risk Score, guarda los hallazgos y los reportes, y borra el clon.
- **Postgres (Supabase):** datos relacionales: organizaciones, usuarios, membresías, repositorios, escaneos y hallazgos.
- **R2 y KV (Cloudflare):** archivos generados (reportes y CBOM) y caché de las consultas a OSV.
- **Workers de Cloudflare:** webhook de GitHub y keep-alive de la API.

Todo el tráfico entre componentes viaja por TLS.

## 3. Infraestructura por componente y justificación

La materia presenta los servicios de AWS; el proyecto usa sus equivalentes con capa gratuita.

| Componente | Servicio | Equivalente en AWS | Módulo | Rol y justificación |
|---|---|---|---|---|
| Frontend | Cloudflare Workers (archivos estáticos) | S3 + CloudFront | B | CDN global, SSL automático y protección DDoS sin servidores propios. |
| API | Render (Web Service, Python) | ECS / App Runner | A | Despliegue continuo desde GitHub y variables de entorno por servicio. |
| Cola de escaneos | Upstash Redis + RQ | SQS | A | Desacopla la API del worker, con reintentos (2), timeout por trabajo (5 min) y cola de errores (se conserva 7 días). |
| Scan-worker | Render (servicio Docker) | ECS / Fargate | A y C | Imagen con Bandit, Semgrep y git; corre con un usuario sin privilegios porque analiza código que no es de confianza. |
| Base de datos | Supabase (Postgres) | RDS | A | Postgres administrado con Row Level Security y backups automáticos. |
| Reportes y CBOM | Cloudflare R2 (S3-compatible) | S3 | D | Almacenamiento de objetos; se descargan con URLs firmadas que vencen en 10 minutos. Sin costo de salida de datos. |
| Caché de OSV | Cloudflare KV (clave-valor) | DynamoDB | D | Guarda la respuesta de OSV por `ecosistema|paquete|versión` con vencimiento de 24 h, para no repetir consultas. |
| Webhook de GitHub | Cloudflare Worker | Lambda + API Gateway | E | Verifica la firma de GitHub y avisa a la API; corre solo cuando llega un push. |
| IA | Gemini API (salida estructurada) | Bedrock | E | Triage de hallazgos y resumen ejecutivo, con caché y fallback si se agota la cuota. |
| Autenticación | Clerk | Cognito | A y B | Login con GitHub, organizaciones, invitaciones y roles, sin manejar contraseñas propias. |
| Keep-alive | Cloudflare Worker con Cron Trigger | EventBridge + Lambda | B | Ping a `/health` cada 10 minutos para que Render free no apague la API. |
| Observabilidad | Better Stack | CloudWatch | B | Logs centralizados y monitoreo de disponibilidad con alertas. |
| CI | GitHub Actions | CodeBuild / CodePipeline | B | Lint y build del frontend y `pytest` del backend en cada pull request. |

## 4. Flujo de escaneo end-to-end

```
POST /repositories/{id}/scans  →  cola (Redis)  →  scan-worker
   │
   ▼
[1] Clonado      git clone --depth 1 en un directorio temporal (límite 50 MB, 120 s)
[2] Motores      SAST │ SCA │ Secretos │ Criptografía, en paralelo
[3] Normalizar   severidad unificada y deduplicación por fingerprint
[4] Triage IA    Gemini: ¿falso positivo?, severidad real y remediación
[5] Risk Score   puntaje 0–100 y nota A–F
[6] Guardar      hallazgos en Postgres; reporte JSON/PDF y CBOM en R2
   │
   ▼
Se borra el clon: Qubitor no conserva el código de los usuarios.
```

1. **Disparo.** Un usuario lanza el escaneo desde el frontend, o GitHub avisa de un push al Worker de webhooks, que lo reenvía firmado a la API. La API crea el registro en `scans` con estado `queued`, publica el trabajo en la cola y responde al instante con el id.
2. **Ejecución.** El worker toma el trabajo, pasa el escaneo a `running`, clona el repo y corre los cuatro motores en paralelo. Todos cumplen el mismo contrato (`backend/app/engines/base.py`): reciben la ruta del repo y devuelven una lista de `Finding`.
3. **Fallas parciales.** Si un motor falla, el error queda en `scans.engine_errors` y los demás siguen: un escaneo parcial es mejor que ninguno. Solo si fallan todos, o falla el clonado, el escaneo termina en `failed`. RQ reintenta el trabajo hasta 2 veces.
4. **Normalización y triage.** Los hallazgos se deduplican por fingerprint (hash de motor, regla, archivo y línea). A Gemini se le envía cada hallazgo con un fragmento mínimo de código, nunca el repo completo, y con los secretos siempre enmascarados.
5. **Resultado.** Se calcula el Risk Score, se guardan los hallazgos en Postgres y los reportes en R2, y el escaneo pasa a `completed`. El frontend consulta el progreso por etapa (polling a `/scans/{id}`).

### Risk Score

```
penalización = Σ peso(severidad)   # hallazgos abiertos y no marcados como falso positivo
risk_score   = max(0, 100 − penalización)
pesos: critical 10 · high 5 · medium 2 · low 0,5 · info 0
nota:  A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40
```

## 5. API

Todos los endpoints, salvo `/health` y el webhook interno, requieren un JWT válido de Clerk. La organización y el rol salen del token en cada pedido.

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/health` | Health check (Render, keep-alive y Better Stack). |
| GET | `/me` | Usuario, rol, organización activa y permisos. |
| GET | `/organization/members` | Miembros de la organización con su rol y última actividad. |
| GET | `/repositories` | Repositorios conectados por la organización. |
| POST | `/repositories` | Conecta un repo público por URL. Solo admin. |
| GET | `/github/repositories` | Repos del usuario en GitHub (OAuth vía Clerk). |
| POST | `/github/repositories` | Conecta uno de esos repos. Solo admin. |
| POST | `/repositories/{id}/scans` | Encola un escaneo. |
| GET | `/repositories/{id}/history` | Historial de escaneos y evolución del Risk Score. |
| GET | `/scans/{id}` | Estado y progreso del escaneo. |
| GET | `/scans/{id}/findings` | Hallazgos del escaneo. |
| GET | `/scans/{id}/summary` | Resumen ejecutivo generado con IA. |
| GET | `/scans/{id}/report` | URLs firmadas para descargar el reporte en JSON y PDF y el CBOM en CycloneDX. |
| PATCH | `/findings/{id}` | Marca un hallazgo como resuelto o falso positivo. |
| POST | `/internal/github/push` | Uso interno del Worker de webhooks; se autentica con firma HMAC, no con JWT. |

## 6. Modelo de datos

Cada dato vive en el almacenamiento que mejor le sirve:

| Dónde | Qué guarda |
|---|---|
| Postgres (Supabase) | Organizaciones, usuarios, membresías, repositorios, escaneos y hallazgos. |
| R2 | Reporte en PDF y JSON y CBOM en CycloneDX 1.6, uno por escaneo. |
| KV | Respuestas de OSV por `ecosistema|paquete|versión`, con vencimiento de 24 h. |
| Redis (Upstash) | Trabajos de la cola mientras esperan o fallaron. No es almacenamiento permanente. |

### Tablas

| Tabla | Campos principales |
|---|---|
| `organizations` | `id`, `name`, `clerk_org_id` (o `user:<id>` para la organización personal). |
| `users` | `id`, `clerk_user_id`, `organization_id` (organización activa). No guarda nombre ni email: se piden a Clerk cuando hacen falta. |
| `memberships` | `user_id`, `organization_id`, `role` (admin/member), `created_at`, `last_seen_at`. |
| `repositories` | `id`, `organization_id`, `full_name`, `url`, `default_branch`, `is_private`, `connected_by_user_id`. |
| `scans` | `id`, `repository_id`, `status` (queued/running/completed/failed), `commit_sha`, `risk_score`, `grade`, `engine_errors`, `error`, `ai_summary`, fechas. |
| `findings` | `id`, `scan_id`, `fingerprint`, `engine`, `rule_id`, `title`, `severity`, `file_path`, `line`, `snippet`, `description`, `cwe`, `cve`, `metadata`, `status` (open/resolved/false_positive) y los campos del triage (`ai_is_false_positive`, `ai_adjusted_severity`, `ai_explanation`, `ai_remediation`). |

### Relaciones

```
organizations 1───N memberships N───1 users
organizations 1───N repositories
repositories  1───N scans
scans         1───N findings
```

Las migraciones se manejan con Alembic (`backend/alembic`).

## 7. Seguridad

- **Autenticación y roles:** Clerk emite el JWT y la API lo valida con las claves públicas de Clerk (JWKS). El rol sale del token: un admin conecta repositorios; un member ve, escanea y marca hallazgos. Si el token trae organización pero no rol, se lo trata como member.
- **Aislamiento entre organizaciones:** cada consulta filtra por la organización del token, y Row Level Security está activado en todas las tablas de Supabase.
- **Webhook:** el Worker verifica la firma HMAC de GitHub y reenvía el evento a la API con su propia firma HMAC con timestamp (`INTERNAL_WEBHOOK_SECRET`). El Worker no tiene acceso a Redis ni a la base.
- **Código ajeno:** el worker corre en Docker con un usuario sin privilegios, clona con límite de tamaño y de tiempo, no sigue enlaces simbólicos fuera del repo y borra el clon al terminar.
- **Secretos encontrados:** se enmascaran antes de guardarse y antes de enviarse a la IA. A Gemini nunca llega el repo completo.
- **Reportes:** el bucket es privado; solo se descarga con URLs firmadas que vencen a los 10 minutos.
- **Secretos propios:** todas las credenciales (`DATABASE_URL`, `REDIS_URL`, `GEMINI_API_KEY`, `CLERK_SECRET_KEY`, `R2_*`, `CF_*`) son variables de entorno en Render y Cloudflare. Ninguna está en el repo; `.env` está en `.gitignore`.
- **CORS** restringido a la URL del frontend (`CORS_ORIGINS`).
- **Trazabilidad:** todo el código generado con IA queda registrado en `docs/AI-DECISIONS.md` con su revisión humana.

## 8. Despliegue y CI/CD

| Pieza | Dónde | Cómo |
|---|---|---|
| Frontend | Cloudflare Workers | `npm run build` y `wrangler deploy` con los archivos estáticos. |
| API | Render (Web Service) | `uvicorn app.main:app`, despliegue automático desde `main`. |
| Scan-worker | Render (servicio Docker) | `backend/worker/Dockerfile`, despliegue automático desde `main`. |
| Base de datos | Supabase | Tablas creadas con `alembic upgrade head`. Render se conecta por el session pooler (no sale por IPv6). |
| Workers | Cloudflare | `infra/webhook-worker` e `infra/worker-keepalive`, cada uno con su `wrangler`. |

Hay un solo entorno desplegado (producción, desde `main`). Para desarrollo, cada integrante corre el backend y el frontend en local con su `.env`; sin `VITE_API_URL`, el frontend usa datos de ejemplo.

### CI (GitHub Actions)

En cada pull request y en cada push a `main` corren el lint y el build del frontend y `pytest` del backend. Para mergear hace falta la CI en verde y la aprobación de otro integrante.

## 9. Escalabilidad y costos

Toda la infraestructura está en planes gratuitos.

| Servicio | Límite del plan gratuito | Cuándo escalar |
|---|---|---|
| Render | 512 MB de RAM; se apaga tras 15 min sin tráfico; horas mensuales limitadas. | Con usuarios concurrentes: plan pago o más instancias del worker (la cola permite sumar workers sin tocar la API). |
| Supabase | 500 MB de base. | Al acumular muchos escaneos históricos. |
| Upstash Redis | Cantidad diaria de comandos limitada. | Con muchos escaneos por día. |
| Cloudflare R2 | 10 GB de almacenamiento, sin costo de salida. | Con miles de reportes guardados; se puede agregar una regla de vencimiento. |
| Cloudflare KV | 100.000 lecturas y 1.000 escrituras por día. | Con muchos paquetes distintos por día. |
| Cloudflare Workers | 100.000 pedidos por día. | Prácticamente no hace falta para el alcance del TP. |
| Gemini API | Pedidos por minuto y por día limitados. | Si la cuota no alcanza en las demos; ya hay caché y fallback a la severidad original. |

El keep-alive no pingea entre las 2 y las 11 UTC (de madrugada en Argentina), para no gastar las horas mensuales de Render cuando nadie usa la app.

## 10. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Render free sin memoria al escanear | El worker se reinicia y el escaneo falla | Clonado superficial, límite de 50 MB, timeout por trabajo y reintentos de la cola. |
| Cold start de Render en la demo | Primer pedido lento | Keep-alive cada 10 minutos. |
| Cuota de Gemini agotada | Hallazgos sin triage | Caché por fingerprint y fallback a la severidad original del motor. |
| OSV lento o caído | SCA tarda o falla | Caché en KV de 24 h; si falla, el resto de los motores sigue. |
| Código malicioso en un repo escaneado | Lectura de archivos del servidor o consumo de recursos | Contenedor sin privilegios, sin seguir enlaces simbólicos, límites de tamaño y tiempo. |
| Filtración de código o secretos de usuarios | Exposición de datos de clientes | No se guarda el código, se borra el clon, los secretos se enmascaran y los reportes solo se bajan con URL firmada. |
| Código generado por IA con errores | Bugs difíciles de rastrear | `AI-DECISIONS.md`, tests obligatorios y revisión cruzada en cada PR. |

## 11. Decisiones de diseño

### SQL y NoSQL: qué va en cada uno

- **Postgres (SQL)** para los datos del negocio. Escaneos, hallazgos y repositorios tienen relaciones (organización → repo → escaneo → hallazgo) y se consultan con filtros, uniones y agregados: hallazgos por severidad, evolución del Risk Score, aislamiento por organización con RLS. Necesitan integridad referencial y transacciones.
- **KV (NoSQL clave-valor)** para la caché de OSV. Se accede siempre por una clave exacta (`ecosistema|paquete|versión`), no hay relaciones ni consultas, el dato puede perderse sin daño (se vuelve a pedir a OSV) y necesita vencimiento automático. KV lo resuelve con TTL nativo y lecturas rápidas desde el borde de la red. En Postgres habría que armar la expiración a mano y se mezclaría información descartable con la del negocio.

### Por qué una cola y no una tarea en segundo plano

Con `BackgroundTasks` el escaneo corría dentro del proceso de la API: competía por los 512 MB con los pedidos de los usuarios, y si Render reiniciaba el servicio el escaneo se perdía sin rastro. Con la cola, la API solo encola y responde; el worker escala por separado; los trabajos sobreviven a reinicios, se reintentan y los que fallan quedan en la cola de errores para revisarlos.

### Por qué los reportes van a un bucket y no a la base

Un PDF o un CBOM son archivos que se escriben una vez y se descargan enteros. Guardarlos en Postgres ocupa la cuota de 500 MB con datos que nunca se consultan por dentro. En un bucket, el navegador los descarga directo con una URL firmada, sin pasar por la API.

### Por qué un Worker para los webhooks

GitHub manda un webhook por push, de forma esporádica. Un Worker serverless solo consume recursos cuando llega uno y filtra en el borde lo que no hace falta procesar: firmas inválidas, eventos que no son push y ramas que no son la principal. Así a la API solo le llegan eventos válidos, firmados con un secreto que GitHub no conoce. La API sigue teniendo que estar despierta para encolar el escaneo; de eso se encarga el keep-alive.
