# Contributing a Qubitor

Guía de trabajo para el equipo (Balda, Pértile de la Vega, Wilt, Marini, Chiappini) en el TPI de Desarrollo de Software Cloud — UTN FRLP, 2026. El objetivo de este documento es que el historial de Git sea evidencia clara y trazable del aporte individual de cada integrante, tal como lo exige la cátedra.

## 1. Flujo de ramas

- `main` — **producción**. Solo se llega vía Pull Request aprobado desde `develop` (o un `hotfix/*`). Cada merge con la CI en verde se despliega en los servicios de producción de Render.
- `develop` — **staging**. Rama de integración: acá se mergean las features. Cada merge con la CI en verde se despliega en los servicios `*-staging` de Render.
- `feature/<área>-<descripción-corta>` — una rama por tarea, que sale de `develop`. Ejemplos:
  - `feature/api-scans-endpoint`
  - `feature/frontend-dashboard-findings`
  - `feature/infra-supabase-rls`
- `hotfix/<descripción-corta>` — solo para un error urgente en producción. Sale de `main`.

No se commitea directo a `main` ni a `develop` bajo ninguna circunstancia, y **nunca se hace force push** a ninguna de las dos: son las ramas que se despliegan (ver [deploy.md](deploy.md)).

### Cómo llega un cambio a Render

Render está conectado directo a este repo y despliega cada rama solo cuando la CI pasó en verde para ese commit:

```
feature/x ──PR──▶ develop ──CI verde──▶ Render staging
                     │
                     └──PR──▶ main ──CI verde──▶ Render producción
```

Un merge está desplegado en unos minutos: lo que tarda la CI más el build de Render.

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

1. Toda rama `feature/*` se mergea a `develop` exclusivamente vía PR. **Nunca un PR de `feature/*` directo a `main`.**
2. **Cross-review obligatorio**: el autor del PR no puede aprobar su propio PR. Debe revisarlo al menos un integrante distinto.
3. El PR debe describir:
   - Qué problema resuelve.
   - Cómo probarlo localmente.
   - Si involucró código generado por IA, referenciar la entrada correspondiente en `AI-DECISIONS.md`.
4. El pipeline de CI (lint, type-check, tests, build) debe pasar en verde antes de mergear.
5. Mantener el título del PR alineado a Conventional Commits. Estrategia de merge según el PR:

| PR | Botón de GitHub | Por qué |
|---|---|---|
| `feature/*` → `develop` | *Squash and merge* o *Create a merge commit* | Cualquiera de las dos. |
| `develop` → `main` | **Create a merge commit** (nunca *Squash*) | Con *Squash*, `main` recibe un commit que `develop` no tiene: las ramas se separan y el próximo PR de `develop` a `main` arrastra cambios viejos o da conflictos. |
| `hotfix/*` → `main` | *Create a merge commit* | Después, abrir enseguida un PR de `main` a `develop` para que staging no pierda el arreglo. |

### Pasar de staging a producción

1. Mergear las features en `develop` y esperar a que se desplieguen en staging.
2. Probar en staging: `https://qubitor-api-staging.onrender.com/health` y un escaneo real con el frontend local apuntando a esa URL (`VITE_API_URL`). Staging en plan free se duerme tras 15 minutos sin uso: el primer pedido tarda ~1 minuto.
3. Abrir un PR de `develop` a `main` titulado `chore(release): …` con la lista de lo que entra. Revisión cruzada como cualquier PR.
4. Mergear con **Create a merge commit**. Cuando la CI de `main` termina en verde, Render lo despliega en producción.
5. Comprobar `https://qubitor-api.onrender.com/health` y la app publicada.

### Si algo no se despliega

- **La CI de `main` o `develop` quedó en rojo después del merge:** Render no despliega ese commit y sigue con la versión anterior. Se arregla con otro PR.
- **La CI está en verde pero Render no desplegó:** en Render, abrir el servicio y mirar *Events*. Se puede forzar con **Manual Deploy** → *Deploy latest commit*. Si sigue sin desplegar, avisar al responsable del Módulo B.

## 4. Gestión de tareas (Kanban)

- Tablero en GitHub Projects con columnas: `Backlog` → `To Do` → `In Progress` → `In Review` → `Done`.
- **Límite de WIP: máximo 2 tareas por integrante en `In Progress`.** No se toma una tarea nueva sin cerrar o pausar explícitamente una anterior.
- Cada tarjeta debe estar asignada a una persona y linkeada a la rama/PR correspondiente.

## 5. Uso de IA

El uso de asistentes de IA (Cursor, GitHub Copilot, Claude, etc.) está fomentado pero bajo control de calidad humano estricto:

- Toda contribución de código o arquitectura generada por IA que se incorpore al proyecto **debe** registrarse en `AI-DECISIONS.md` antes de mergear el PR correspondiente.
- El responsable final del código es quien lo mergea, no la IA. Revisar output generado con el mismo rigor que código propio: buscar alucinaciones, riesgos de seguridad e ineficiencias.

## 6. Checklist antes de abrir un PR

- [ ] La rama sale de `develop` y el PR apunta a `develop` (o `develop` → `main` para pasar a producción).
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
