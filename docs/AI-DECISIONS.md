# AI-DECISIONS.md

Log de auditoría de las decisiones técnicas y de arquitectura asistidas por IA durante el desarrollo de **Qubitor** (TPI — Desarrollo de Software Cloud, UTN FRLP, 2026). Cada entrada documenta el razonamiento detrás de código o diseño generado con un asistente de IA, y la validación/corrección humana aplicada antes de mergear a `main`.

Este archivo es obligatorio en la raíz del repositorio y es evidencia directa de integridad profesional y criterio técnico ante la cátedra: **toda incorporación de código o arquitectura generada por IA debe tener una entrada acá antes de abrir el PR correspondiente.**

## Cómo agregar una entrada

Copiar el bloque de abajo, completar los campos y agregarlo al final de este archivo (orden cronológico). Referenciar el número de PR cuando exista.

```markdown
### [AAAA-MM-DD] <Título corto de la decisión>

- **Problema abordado:** <descripción del desafío técnico>
- **Prompt / Herramienta utilizada:** <instrucción exacta enviada y asistente empleado>
- **Código / Arquitectura generada:** <resumen de lo que propuso la IA>
- **Validación y Corrección Humana:** <qué se identificó como alucinación, ineficiencia o riesgo de seguridad, y cómo se corrigió>
- **Responsable:** <integrante que revisó/mergeó>
- **PR:** #<número>
```

---

## Registro de decisiones

### [2026-09-27] Elección de arquitectura desacoplada de tres capas

- **Problema abordado:** Definir una infraestructura cloud-native para el MVP que minimice carga operativa (sin servidores propios) cumpliendo con el requisito de la cátedra de justificar cada componente por escalabilidad, costos y arquitectura.
- **Prompt / Herramienta utilizada:** Discusión asistida sobre trade-offs entre servicios gestionados de frontend (Cloudflare Pages vs. Vercel), backend (Render vs. AWS Lambda) y persistencia (Supabase vs. RDS/DynamoDB) para un equipo de 5 personas con foco académico y presupuesto free-tier.
- **Código / Arquitectura generada:** Propuesta de stack: React en Cloudflare Pages (frontend), FastAPI en Render (backend), Postgres administrado por Supabase con Row Level Security, Gemini API para evaluación de hallazgos, Clerk/Auth0 para autenticación.
- **Validación y Corrección Humana:** Se evaluó el riesgo de cold start en el plan free de Render (apagado tras 15 min de inactividad) — mitigado agregando un Cloudflare Worker con Cron Trigger que hace keep-alive cada 10 min a `/health`. Se descartó AWS Lambda como backend por la complejidad adicional de empaquetado de dependencias Python pesadas (motores de escaneo) frente al beneficio marginal para el volumen esperado del MVP académico.
- **Responsable:** Equipo Qubitor (revisión conjunta)
- **PR:** —

### [PLANTILLA — completar en próximas entradas]

- **Problema abordado:**
- **Prompt / Herramienta utilizada:**
- **Código / Arquitectura generada:**
- **Validación y Corrección Humana:**
- **Responsable:**
- **PR:** #
