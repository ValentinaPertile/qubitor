# AI Decision Log (`AI-DECISIONS.md`)

Este archivo registra y audita de forma continua todas las decisiones de arquitectura, diseño y fragmentos de código generados con la asistencia de Inteligencia Artificial (asistentes LLM, Cursor, Gemini, Copilot), detallando el razonamiento técnico, el contexto y la validación/corrección humana realizada por el equipo de ingeniería.

---

## Estructura de Registro

Cada entrada debe documentar:
- **Problema abordado:** Descripción del desafío técnico.
- **Prompt / Herramienta utilizada:** Instrucción enviada y asistente empleado.
- **Código / Arquitectura generada:** Resumen de la propuesta de la IA.
- **Validación y Corrección Humana:** Análisis crítico donde se identifiquen y corrijan alucinaciones, ineficiencias de rendimiento o riesgos de seguridad.

---

## Entradas del Proyecto

### 1. Definición Inicial de la Arquitectura Cloud y Selección de Stack (2026-08-27)
- **Problema abordado:** Definir el stack tecnológico y la arquitectura cloud para una plataforma SaaS de auditoría criptográfica post-cuántica (PQC), garantizando costo $0 operativo para el MVP, alta disponibilidad y cumplimiento de las directrices Cloud-Native de la cátedra.
- **Prompt / Herramienta utilizada:** Antigravity / Gemini 3.7 - Evaluación y diseño de stack para SaaS con backend en Python, frontend en React, persistencia PostgreSQL y motor de IA.
- **Código / Arquitectura generada:** Se propuso una arquitectura desacoplada basada en Cloudflare Pages (Frontend SPA), Render (Backend API en FastAPI con contenedores), Supabase (PostgreSQL serverless administrado + Auth + Storage), Google Gemini API (análisis contextual de vulnerabilidades PQC) y Cloudflare Workers (Keep-Alive cron trigger).
- **Validación y Corrección Humana:** 
  - Se validó la separación estricta de la capa de persistencia (Supabase) y la capa de cómputo (Render) para mantener el backend completamente *stateless*, facilitando el escalado horizontal.
  - Se confirmó el uso de Row Level Security (RLS) en PostgreSQL para aislamiento nativo multi-tenant por usuario/organización.
  - Se verificó la adopción de esquemas de respuesta tipados con Pydantic para validar estructuradamente las respuestas de la Gemini API y prevenir alucinaciones en los reportes de remediación post-cuántica.

---
