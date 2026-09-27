# Contributing a Qubitor

Guía de trabajo para el equipo (Balda, Pértile de la Vega, Wilt, Marini, Chiappini) en el TPI de Desarrollo de Software Cloud — UTN FRLP, 2026. El objetivo de este documento es que el historial de Git sea evidencia clara y trazable del aporte individual de cada integrante, tal como lo exige la cátedra.

## 1. Flujo de ramas

- `main` — rama protegida. Solo se llega vía Pull Request aprobado. Cada merge a `main` dispara el deploy automático (Render + Cloudflare Pages).
- `develop` — rama de integración (staging opcional). Acumula features antes de promocionar a `main`.
- `feature/<área>-<descripción-corta>` — una rama por tarea. Ejemplos:
  - `feature/api-scans-endpoint`
  - `feature/frontend-dashboard-findings`
  - `feature/infra-supabase-rls`

No se commitea directo a `main` ni a `develop` bajo ninguna circunstancia.

## 2. Conventional Commits

Todo commit debe seguir [Conventional Commits](https://www.conventionalcommits.org/):

```
<tipo>(<alcance opcional>): <descripción corta en imperativo>

[cuerpo opcional explicando el porqué]

[footer opcional: refs #issue, BREAKING CHANGE, etc.]
```

Tipos permitidos:

| Tipo | Uso |
|---|---|
| `feat` | Nueva funcionalidad |
| `fix` | Corrección de un bug |
| `docs` | Cambios de documentación (README, AI-DECISIONS.md, etc.) |
| `refactor` | Cambio de código sin alterar comportamiento |
| `test` | Agregar o corregir tests |
| `chore` | Tareas de mantenimiento (deps, configs, CI) |
| `perf` | Mejora de rendimiento |

Ejemplos válidos:

```
feat(api): agregar endpoint POST /repositories/{id}/scans
fix(auth): corregir validación de JWT expirado en middleware
docs(ai-decisions): registrar decisión sobre índice de findings por severidad
```

**Prohibido:** commits gigantes de último momento ("final version", "arreglos varios", "wip"). Cada commit debe representar una unidad de trabajo coherente y revisable. La cátedra audita frecuencia, calidad y autoría — commitear seguido y en chico es parte de la nota.

## 3. Pull Requests

1. Toda rama `feature/*` se mergea a `develop` (o `main` si no se usa staging) exclusivamente vía PR.
2. **Cross-review obligatorio**: el autor del PR no puede aprobar su propio PR. Debe revisarlo al menos un integrante distinto.
3. El PR debe describir:
   - Qué problema resuelve.
   - Cómo probarlo localmente.
   - Si involucró código generado por IA, referenciar la entrada correspondiente en `AI-DECISIONS.md`.
4. El pipeline de CI (lint, type-check, tests, build) debe pasar en verde antes de mergear.
5. Usar "Squash and merge" o "Merge commit" según se acuerde en el equipo, pero mantener el título del PR alineado a Conventional Commits.

## 4. Gestión de tareas (Kanban)

- Tablero en GitHub Projects con columnas: `Backlog` → `To Do` → `In Progress` → `In Review` → `Done`.
- **Límite de WIP: máximo 2 tareas por integrante en `In Progress`.** No se toma una tarea nueva sin cerrar o pausar explícitamente una anterior.
- Cada tarjeta debe estar asignada a una persona y linkeada a la rama/PR correspondiente.

## 5. Uso de IA

El uso de asistentes de IA (Cursor, GitHub Copilot, Claude, etc.) está fomentado pero bajo control de calidad humano estricto:

- Toda contribución de código o arquitectura generada por IA que se incorpore al proyecto **debe** registrarse en `AI-DECISIONS.md` antes de mergear el PR correspondiente.
- El responsable final del código es quien lo mergea, no la IA. Revisar output generado con el mismo rigor que código propio: buscar alucinaciones, riesgos de seguridad e ineficiencias.

## 6. Checklist antes de abrir un PR

- [ ] Commits siguen Conventional Commits.
- [ ] Código con lint/type-check en verde localmente.
- [ ] Tests agregados o actualizados si corresponde.
- [ ] Si hubo asistencia de IA relevante, entrada agregada en `AI-DECISIONS.md`.
- [ ] Sin secretos ni credenciales committeadas (revisar `.env` vs `.gitignore`).
- [ ] Tarjeta de Kanban movida a `In Review`.

## 7. Setup local

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

Variables de entorno: copiar `.env.example` a `.env` en cada carpeta y completar con los valores de Supabase, Gemini API y el proveedor de auth (Clerk/Auth0). Nunca commitear `.env`.
