# Arquitectura — Qubitor

> Trabajo Práctico Integrador — Desarrollo de Software Cloud, UTN FRLP (2026)
> Checkpoint 1: Definición de Arquitectura

## 1. Alcance del documento

Este documento define la arquitectura técnica y la infraestructura cloud propuesta para Qubitor, plataforma de auditoría continua de seguridad con evaluación de hallazgos asistida por IA. Cubre: componentes del sistema, infraestructura por servicio, flujo de datos, modelo de datos preliminar, diseño de API, seguridad, estrategia de despliegue/CI-CD, escalabilidad, costos estimados y riesgos identificados.

El detalle de implementación de cada motor de escaneo (reglas de SAST, fuentes de CVEs para SCA, patrones de detección de secretos y criterios de criptografía post-cuántica) se profundizará en etapas posteriores; acá se define el esqueleto de la plataforma que los va a alojar.

## 2. Arquitectura general

Arquitectura desacoplada de tres capas (frontend, API, datos) más servicios administrados externos, todos sobre infraestructura serverless / managed, sin servidores propios que mantener. La API centraliza toda la lógica de negocio y es el único componente que habla con la base de datos y con los servicios externos.

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

### Responsabilidad de cada capa

- **Frontend**: SPA en React que consume la API vía HTTPS/JSON. No contiene lógica de negocio sensible ni credenciales de servicios externos.
- **Backend**: única API FastAPI que orquesta los motores de escaneo, valida autenticación, aplica reglas de negocio y concentra las integraciones externas (repos, IA, auth).
- **Datos**: Postgres administrado por Supabase, con RLS activado para que cada organización solo pueda leer y escribir sus propios registros.

Todo el tráfico externo (Cloudflare ↔ Render ↔ Supabase ↔ APIs externas) viaja cifrado por TLS; no hay comunicación en texto plano en ningún tramo.

## 3. Infraestructura por componente y justificación

| Componente | Plataforma | Rol y justificación |
|---|---|---|
| Frontend | Cloudflare Pages | Hosting estático + CDN global Anycast con despliegue continuo desde Git. Se eligió por su capa gratuita, SSL automático y protección DDoS incluida, sin necesidad de configurar servidores propios. |
| Backend / API | Render (Web Service) | Contenedor Python que corre FastAPI. Se eligió por su simplicidad de despliegue continuo desde GitHub, soporte nativo de variables de entorno y Blueprints (`render.yaml`) para reproducir el entorno. |
| Base de datos | Supabase (Postgres) | Postgres administrado con alta disponibilidad, políticas de RLS a nivel de fila y backups automáticos diarios, evitando administrar un motor de base de datos propio. |
| IA | Gemini API | Servicio externo invocado por el backend para clasificar hallazgos, descartar falsos positivos y generar la hoja de ruta de remediación en lenguaje natural. |
| Autenticación | Clerk / Auth0 | Identity provider gestionado que delega el manejo seguro de credenciales, OAuth con GitHub/GitLab y emisión de tokens JWT que el backend valida en cada request. |
| Keep-alive | Cloudflare Worker + Cron Trigger | Ping cada 10 minutos a `/health` en Render, para evitar el apagado por inactividad propio del plan free y reducir la latencia del primer request de cada usuario. |
| Observabilidad | Better Stack | Centraliza logs del backend en Render y monitorea la disponibilidad (uptime) de la API con alertas. |

## 4. Flujo de escaneo end-to-end

Secuencia completa desde que un equipo conecta su repositorio hasta que recibe el reporte priorizado:

1. **Conexión.** El usuario se autentica (Clerk/Auth0) y autoriza a Qubitor a leer sus repositorios vía OAuth de GitHub/GitLab. El backend guarda la referencia del repositorio en la tabla `repositories`.
2. **Disparo del escaneo.** Un escaneo se dispara manualmente desde el frontend o automáticamente por webhook en cada push. El backend crea un registro en `scans` con estado `pending`.
3. **Ejecución de los motores.** El backend descarga o clona el contenido necesario y ejecuta en paralelo los cuatro motores: SAST (patrones de código inseguro), SCA (dependencias vs. bases de CVEs como OSV/NVD), secret scanning y auditoría de criptografía vulnerable.
4. **Agregación de hallazgos.** Cada motor persiste sus resultados crudos en `findings`, asociados al scan correspondiente, con severidad preliminar y categoría.
5. **Evaluación con IA.** El backend envía el conjunto de hallazgos a Gemini API, que descarta falsos positivos, re-prioriza por severidad real en el contexto del proyecto y redacta sugerencias de remediación en lenguaje natural.
6. **Reporte accionable.** El resultado final se persiste y se expone vía API al frontend, que renderiza el dashboard con el reporte priorizado y la hoja de ruta de remediación.

> Los pasos 3 y 5 son los de mayor costo computacional/tiempo; se ejecutan de forma asíncrona (tarea en background) para no bloquear el request HTTP del usuario.

## 5. Diseño preliminar de la API

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/health` | Health check usado por Render y el Worker de keep-alive. |
| POST | `/auth/callback` | Callback de OAuth de Clerk/Auth0 tras la autenticación del usuario. |
| GET | `/repositories` | Lista los repositorios conectados por la organización autenticada. |
| POST | `/repositories` | Conecta un nuevo repositorio (guarda referencia y permisos de acceso). |
| POST | `/repositories/{id}/scans` | Dispara un nuevo escaneo sobre un repositorio conectado. |
| GET | `/scans/{id}` | Consulta el estado y progreso de un escaneo (pending/running/done). |
| GET | `/scans/{id}/findings` | Devuelve el reporte de hallazgos priorizado por severidad. |
| PATCH | `/findings/{id}` | Actualiza el estado de un hallazgo (ej. marcarlo como resuelto). |

Todos los endpoints (salvo `/health`) requieren un token JWT válido emitido por el proveedor de auth, validado en middleware antes de llegar al handler.

## 6. Modelo de datos

| Entidad | Campos principales / relación |
|---|---|
| `organizations` | `id` (PK), nombre, plan (free/team/business/enterprise), creado_en. |
| `users` | `id` (PK), `organization_id` (FK → organizations), email, rol (admin/miembro), proveedor_auth. |
| `repositories` | `id` (PK), `organization_id` (FK), proveedor (GitHub/GitLab), url, conectado_en. |
| `scans` | `id` (PK), `repository_id` (FK → repositories), estado, motor(es) ejecutados, iniciado_en, finalizado_en. |
| `findings` | `id` (PK), `scan_id` (FK → scans), severidad, categoría, descripción, remediación_sugerida, estado (abierto/resuelto). |
| `api_keys` | `id` (PK), `organization_id` (FK), hash de la clave, alcance, creado_en, último_uso (para integraciones CI/CD futuras). |

### Relaciones

```
organizations 1───N users
organizations 1───N repositories
repositories  1───N scans
scans         1───N findings
organizations 1───N api_keys
```

Diseño normalizado y preliminar; se ajustará al definir en detalle cada motor de escaneo.

## 7. Seguridad y gestión de secretos

- Autenticación centralizada vía Clerk/Auth0; el backend nunca almacena contraseñas y solo valida tokens JWT firmados.
- CORS restringido en el backend únicamente a los dominios de frontend autorizados (variable `ALLOWED_ORIGINS`).
- Secretos (`DATABASE_URL`, `GEMINI_API_KEY`, claves de auth) gestionados como variables de entorno en Render, nunca committeados al repositorio; auditoría rigurosa de `.gitignore` desde el primer commit.
- Row Level Security en Supabase para aislar datos entre organizaciones a nivel de fila, no solo a nivel de aplicación.
- Trazabilidad de código generado por IA documentada en `AI-DECISIONS.md`, con revisión humana obligatoria antes de mergear a `main`.
- Conventional Commits + Pull Requests cruzados entre integrantes, para que el historial de Git sea evidencia trazable del aporte individual.

## 8. Estrategia de despliegue y CI/CD

### Entornos

| Entorno | Rama de origen | Destino |
|---|---|---|
| Desarrollo local | Cualquier rama de feature | Backend y frontend corridos localmente con `.env` propios. |
| Staging (opcional) | `develop` | Deploy de prueba en Render/Cloudflare Pages con datos de prueba, antes de mergear a `main`. |
| Producción | `main` | Deploy automático en Render (backend) y Cloudflare Pages (frontend) tras cada merge aprobado. |

### Pipeline de CI (GitHub Actions)

- Lint y type-check del frontend (TypeScript/ESLint) en cada Pull Request.
- Lint y tests del backend (`pytest`) en cada Pull Request.
- Build de verificación del frontend (`npm run build`) antes de permitir el merge.
- El deploy real queda delegado a Render y Cloudflare Pages, que despliegan automáticamente al detectar un push a `main` (no se gestiona manualmente).

## 9. Escalabilidad y estimación de costos

Durante el desarrollo del TP, toda la infraestructura se mantiene en los planes gratuitos de cada proveedor.

| Servicio | Límite plan free | Cuándo escalar |
|---|---|---|
| Render | Se apaga tras 15 min de inactividad; recursos compartidos limitados. | Con usuarios reales concurrentes o si el keep-alive no alcanza a sostener la latencia esperada. |
| Supabase | 500 MB de base de datos, 2 proyectos activos. | Al superar el volumen de hallazgos históricos o necesitar más de un entorno (staging + producción). |
| Cloudflare Pages | Builds y ancho de banda generosos, sin costo relevante en esta etapa. | Prácticamente no requiere escalar para el alcance del TP. |
| Gemini API | Cuota gratuita con límite de requests por minuto. | Si el volumen de hallazgos a evaluar supera la cuota gratuita durante las demos. |

## 10. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Cold start de Render afecta la demo en vivo | Latencia alta o timeout en el primer request | Cloudflare Worker con Cron Trigger haciendo ping cada 10 min a `/health`. |
| Cuota gratuita de Gemini API insuficiente el día de la demo | Evaluación de hallazgos falla o se degrada | Cachear resultados de IA por hallazgo y tener un fallback con evaluación heurística simple. |
| Fuga de secretos en el repositorio | Exposición de credenciales de servicios externos | `.gitignore` auditado desde el primer commit + revisión en cada Pull Request. |
| Código generado por IA con errores no detectados | Bugs difíciles de rastrear en producción | `AI-DECISIONS.md` + revisión humana obligatoria antes de mergear a `main`. |
| Cambios de alcance sobre la marcha (sin consigna formal) | Retrabajo o desalineación con lo que evalúa la cátedra | Consultar al profesor/JTP en cada checkpoint y ajustar este documento en consecuencia. |
