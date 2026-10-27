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
- **Responsable:** Equipo en conjunto
- **PR:** #5

### [2026-10-27] Detector de criptografía post-cuántica para Python (pqc.py)

- **Problema abordado:** Detectar en repositorios Python el uso de algoritmos vulnerables a computación cuántica (RSA, DSA, ECDSA, ECDH y DH por el algoritmo de Shor; AES-128 por el de Grover) y registrar la criptografía segura (AES-256, SHA-2/SHA-3, BLAKE2, Argon2, ChaCha20-Poly1305) como inventario criptográfico (CBOM), respetando el contrato común de motores (`Finding`, `Severity`).
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), trabajando de forma incremental bajo mi guía: yo definí el orden y el ritmo de los pasos, aprobé cada uno antes de su commit y pedí explicaciones línea por línea de cada pieza antes de avanzar. Decisiones mías durante el proceso: no commitear `base.py` (es del Módulo A; se usa una copia local hasta que se publique), exponer `scan_pqc` sin modificar `engines/crypto/__init__.py` hasta coordinarlo con el Módulo C, y dividir el inventario en pasos separados. Pasos: recorrido y parseo de archivos; RSA; ECDSA/ECDH; DH; AES según tamaño de clave; inventario de hashes, Argon2 y ChaCha20; soporte de pycryptodome, rsa y ecdsa, y DSA.
- **Código / Arquitectura generada:** `backend/app/engines/crypto/pqc.py` con la función pública `scan_pqc(repo_path)`. Analiza el código con el módulo `ast` en lugar de buscar texto: arma un mapa de imports para resolver el nombre completo de cada función llamada (soporta alias e imports directos, y distingue librerías con nombres iguales) y lo compara contra una tabla de reglas (`CALL_RULES`). Para AES, una función elige la severidad según el tamaño de clave escrito en la llamada. Reglas con prefijo `crypto.pqc.*` e inventario como `crypto.pqc.inventory.*` con severidad `info`. Librerías cubiertas: cryptography, pycryptodome, rsa, ecdsa, hashlib y argon2-cffi. 33 tests en `backend/tests/engines/test_pqc.py`, con casos positivos y negativos.
- **Validación y Corrección Humana:** Revisé cada paso antes de su commit y pedí la explicación línea por línea de cada función hasta entenderla (recorrido de archivos, mapa de imports, resolución de nombres y reglas). Ejecuté la suite de tests (33 tests, todos pasan) y verifiqué que fallen al quitar una regla. Validé que los casos negativos eviten falsos positivos: comentarios y textos que mencionan algoritmos, objetos propios con nombres como `rsa` y librerías con nombres iguales. Dejé MD5 y SHA-1 fuera del módulo a propósito porque corresponden a criptografía clásica (Módulo C). Limitaciones identificadas y aceptadas para el MVP: el análisis no sigue variables (por ejemplo, `parametros.generate_private_key()` no se detecta, aunque sí el `dh.generate_parameters` que lo origina); con `algorithms.AES(clave)` no se puede determinar el tamaño de la clave, así que se registra como inventario sin tamaño; todavía no se cubren X25519/Ed25519 ni la carga de claves con `RSA.import_key`. Pendiente coordinar con el Módulo C: RSA de menos de 2048 bits puede reportarse dos veces (como `high` en classic.py y como `medium` acá). En una revisión de seguridad que pedí antes de abrir el PR se encontraron y corrigieron dos problemas, verificados con archivos de prueba armados a propósito: (1) el detector seguía enlaces simbólicos, por lo que un repo malicioso podía hacerle leer archivos del servidor y filtrar su contenido en el reporte; ahora se saltean los enlaces y todo archivo que quede fuera del repo; (2) el `snippet` mostraba las claves escritas en el código (por ejemplo, `AES.new(b'clave')`), que se guardarían en la base y se enviarían a la IA, violando el contrato; ahora todo texto o bytes del snippet se reemplaza por `'***'` y el snippet se recorta a 200 caracteres. Se agregaron 4 tests que cubren estos casos.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** feat(pqc): detector de criptografía post-cuántica para Python



### [PLANTILLA — completar en próximas entradas]

- **Problema abordado:**
- **Prompt / Herramienta utilizada:**
- **Código / Arquitectura generada:**
- **Validación y Corrección Humana:**
- **Responsable:**
- **PR:** #
