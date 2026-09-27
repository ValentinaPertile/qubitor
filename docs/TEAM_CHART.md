# Team Chart — Qubitor

Distribución de roles y responsabilidades del equipo para el TPI de Desarrollo de Software Cloud (UTN FRLP, 2026). Este documento es referencia para la cátedra a la hora de auditar la participación individual de cada integrante contra el historial de Git.

## Integrantes y rol principal

| Integrante | Legajo | Rol principal | Área(s) de responsabilidad |
|---|---|---|---|
| Wilt, Juan Ignacio | 33151 | Tech Lead / Infraestructura | Arquitectura general, CI/CD, despliegue (Render, Cloudflare Pages), observabilidad |
| Balda, Matías | 33460 | Backend | API FastAPI, orquestación de motores de escaneo, modelo de datos |
| Pértile de la Vega, Valentina | 33288 | Frontend | SPA React, dashboard de hallazgos, UX del flujo de conexión de repos |
| Marini, Alvaro | 33133 | Backend / Seguridad | Motores SAST/SCA/secret scanning, integración con Supabase (RLS) |
| Chiappini, Valentino | 33072 | IA / Integraciones | Integración con Gemini API, lógica de priorización de hallazgos, auth (Clerk/Auth0) |

> Los roles son de **foco principal**, no exclusivos: se espera cross-review de PRs entre todos los integrantes (ver `CONTRIBUTING.md`), y cualquiera puede tomar tareas fuera de su área si el Kanban lo requiere.

## Matriz RACI por componente

R = Responsable (ejecuta) · A = Accountable (aprueba/dueño) · C = Consultado · I = Informado

| Componente | Wilt | Balda | Pértile de la Vega | Marini | Chiappini |
|---|---|---|---|---|---|
| Arquitectura general | A/R | C | C | C | C |
| Frontend (React) | I | C | A/R | I | C |
| Backend / API (FastAPI) | C | A/R | I | R | C |
| Motores de escaneo (SAST/SCA/secrets) | C | R | I | A/R | I |
| Base de datos (Supabase + RLS) | C | R | I | A/R | I |
| Integración IA (Gemini) | I | C | I | C | A/R |
| Autenticación (Clerk/Auth0) | I | C | C | I | A/R |
| CI/CD (GitHub Actions) | A/R | C | C | C | I |
| Despliegue (Render + Cloudflare Pages) | A/R | I | I | I | I |
| Observabilidad (Better Stack) | A/R | I | I | I | I |
| Documentación (README, AI-DECISIONS, arquitectura) | R | R | R | R | R |

## Comunicación y ritmo de trabajo

| Instancia | Frecuencia | Objetivo |
|---|---|---|
| Standup asincrónico (Discord/WhatsApp) | Diario | Bloqueos, qué se está tomando del Kanban |
| Revisión de PRs cruzados | Continua | Cross-review obligatorio antes de mergear (ver `CONTRIBUTING.md`) |
| Sync de arquitectura | Antes de cada checkpoint | Alinear decisiones de infraestructura y actualizar `AI-DECISIONS.md` |
