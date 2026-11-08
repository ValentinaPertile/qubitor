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
- **PR:** #8

### [2026-11-02] Motor SCA de dependencias vulnerables con OSV (engines/sca)

- **Problema abordado:** Detectar dependencias con vulnerabilidades conocidas (CVE) en repositorios Python y JavaScript, informando gravedad, versión corregida y comando de actualización, como `Engine` del contrato común.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5). Aprobé el plan de 6 pasos antes de empezar (un commit por paso) y las decisiones de diseño: no sumar librerías y usar la gravedad que calcula GitHub para el MVP.
- **Código / Arquitectura generada:** `backend/app/engines/sca/` en cuatro módulos: `manifests.py` (lee versiones exactas de `requirements*.txt`, `package.json` y `package-lock.json` v1/v2/v3, prefiriendo el lock), `osv.py` (cliente de la API de OSV con `urllib`: `querybatch` en lotes y detalle por ID), `findings.py` (convierte cada vulnerabilidad en `Finding` con CVE, CWE, gravedad, vector CVSS, versión corregida y comando `pip`/`npm`) y `engine.py` (`ScaEngine`: pide los detalles en paralelo, una vez por ID, y elimina las fallas repetidas con distinto ID usando los alias). 32 tests sin red con un OSV simulado, más un test opcional contra OSV real (`QUBITOR_TESTS_RED=1`).
- **Validación y Corrección Humana:** Revisé el plan antes de empezar y el resultado de cada paso. Ejecuté la suite de tests (32 sin red, todos pasan) y el test contra OSV real, que detecta CVE-2018-18074 en requests 2.19.0 y CVE-2019-10744 en lodash 4.17.4. Escaneé el repo de demo: 15 vulnerabilidades en unos 2 segundos, dentro del límite de 60 s del contrato. Durante el desarrollo se encontraron y corrigieron dos fallas, cada una con su test: un `package-lock.json` mal formado hacía fallar la lectura, y los campos en `null` de las entradas PYSEC de OSV rompían la conversión. Verifiqué que la misma falla publicada con dos IDs (GHSA y PYSEC) aparezca una sola vez y con la gravedad de GitHub, que la versión corregida se elija dentro de la rama instalada y comparando versiones como números (4.17.12 > 4.17.5), y que no se sigan enlaces a archivos fuera del repo. Limitaciones aceptadas para el MVP: solo se analizan versiones exactas (los rangos como `^4.17.4` se saltean si no hay lock); la gravedad se toma de GitHub y, si falta, se asume `medium` y queda marcada como desconocida; todavía no hay caché de OSV (se agrega con Cloudflare KV); si OSV no responde, el motor lanza `OsvError` para que el orquestador lo registre.
### [2026-11-02] Detector de criptografía post-cuántica para JavaScript (pqc.py)

- **Problema abordado:** Extender el detector post-cuántico a JavaScript y TypeScript (módulo `crypto` de Node.js), necesario para la falla plantada en `app/signing.js` del repo de demo.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), trabajando de forma incremental bajo mi guía: aprobé el enfoque y el commit, y pedí la explicación de cada pieza antes de avanzar.
- **Código / Arquitectura generada:** Detección con expresiones regulares (`JS_RULES`) sobre el código sin comentarios, reutilizando las mismas reglas que Python. Cubre `generateKeyPair(Sync)` (RSA, EC, DSA, DH), `createECDH`, `createDiffieHellman`, `createCipheriv` (AES por tamaño y ChaCha20) y `createHash` (inventario). Una función propia quita los comentarios `//` y `/* */` respetando los textos entre comillas y conservando los números de línea. El snippet se corta en el nombre del algoritmo para no incluir claves. Se generalizaron `_iter_files`, `_read_text` y `_make_finding` para los dos lenguajes. 9 tests nuevos (46 en total).
- **Validación y Corrección Humana:** Revisé la explicación de cada pieza antes del commit (patrones de `JS_RULES`, quitado de comentarios y armado del snippet). Ejecuté la suite de tests (46 tests, todos pasan) y escaneé el repo de demo `qubitor-demo-vulnerable`: la falla plantada en `app/signing.js` aparece como `crypto.pqc.ec-keygen` en la línea correcta. Validé los casos negativos: comentarios `//` y `/* */` que mencionan funciones criptográficas, URLs con `//` dentro de textos, tipos de clave ya post-cuánticos (`ml-dsa-65`) y MD5, que corresponde al Módulo C. Verifiqué que el snippet no incluya la clave pasada a `createCipheriv`. Decidí usar expresiones regulares en lugar de un parser de JavaScript para no sumar dependencias al scan-worker, aceptando estas limitaciones para el MVP: no se resuelve de dónde viene cada nombre (una función propia llamada `createECDH` también se detectaría), no se cubre WebCrypto (`crypto.subtle`), y como `crypto.sign` no indica el algoritmo, la firma ECDSA de la demo se reporta como generación de clave de curva elíptica (el riesgo es el mismo).
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #9



### [2026-11-02] Contrato común entre motores (base.py)

- **Problema abordado:** Publicar la interfaz que comparten todos los motores (`Severity`, `Finding`, `Engine`) para que cada módulo desarrolle y pruebe su motor por separado y el orquestador los integre sin cambios. Los Módulos D (pqc y SCA) venían usando una copia local porque el archivo no estaba en `main`.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5): pedí escribir `backend/app/engines/base.py` siguiendo al pie de la letra la sección 3 del plan de desarrollo, con tests.
- **Código / Arquitectura generada:** `base.py` con `Severity` (enum de texto: critical, high, medium, low, info), el dataclass `Finding` y la clase abstracta `Engine` con `scan(repo_path) -> list[Finding]`. 8 tests en `backend/tests/engines/test_base.py`: severidad desde texto y como texto, valores inválidos, campos opcionales por defecto, `metadata` independiente entre hallazgos y que un motor sin `scan` no se pueda instanciar.
- **Validación y Corrección Humana:** Verifiqué que los campos coincidan con el plan y con el uso que ya hacen `pqc.py` y el motor SCA (`cwe`, `cve`, `metadata`, `line`). Corrí la suite de pqc y la del SCA (desde su rama) contra este `base.py`: pasan todas salvo los tests de enlaces simbólicos, que fallan solo en Windows porque crear symlinks requiere permisos de administrador (no tiene relación con el contrato). Se dejó fuera del contrato el fingerprint y los pesos de severidad: son parte de la normalización y del Risk Score del orquestador.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(engines): publicar el contrato común entre motores (base.py)

### [2026-11-02] Orquestador del escaneo (normalización, Risk Score y ejecución de motores)

- **Problema abordado:** Ejecutar todos los motores sobre un repo clonado sin que la falla de uno arruine el escaneo, unificar sus hallazgos sin duplicados y calcular el Risk Score y la nota A–F (etapas 2, 3 y 5 del pipeline).
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), de a un paso por commit: (1) fingerprint y deduplicación, (2) Risk Score y nota, (3) ejecución en paralelo con timeout, (4) pipeline que une todo.
- **Código / Arquitectura generada:** `backend/app/orchestrator/`: `normalize.py` (fingerprint SHA-256 de motor + regla + archivo + línea; ante duplicados se queda el de mayor severidad), `risk.py` (pesos y umbrales de la sección 5 del plan; recibe solo las severidades que cuentan, así la API lo puede recalcular al marcar hallazgos como resueltos o falsos positivos), `runner.py` (`ThreadPoolExecutor` con un hilo por motor y límite de 70 s; los errores y timeouts quedan en un dict por motor) y `pipeline.py` (`analyze_repository(repo_path, engines)` → `ScanResult` con hallazgos por fingerprint, errores, score, nota y duración). 33 tests en `backend/tests/orchestrator/`.
- **Validación y Corrección Humana:** El orquestador recibe la lista de motores en lugar de importarlos, así se testea con motores falsos (que fallan, que se cuelgan, que tardan) y no depende de que estén mergeados. El fingerprint no incluye snippet ni severidad para que el mismo problema se reconozca entre escaneos aunque cambie el código vecino o la IA ajuste la severidad. Limitación aceptada: un hilo de Python no se puede cortar desde afuera, así que un motor colgado sigue corriendo después del timeout; se mitiga con los timeouts propios de cada motor (Bandit 50 s) y con que el scan-worker procesa un escaneo por proceso. Queda para el scan-worker: clonado (Módulo E), triage con IA entre la normalización y el score (Módulo E) y persistencia (modelos de Alvaro).
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(orchestrator): orquestador del escaneo
### [2026-11-02] Motor SAST con Bandit (SastEngine)

- **Problema abordado:** Detectar código inseguro en repos Python (eval/exec, SQL armada con strings, `shell=True`, pickle, YAML inseguro, TLS sin verificar, etc.) y devolverlo con el contrato común, para la vista «Código inseguro» y el Risk Score.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), de a un paso por commit: (1) ejecutar Bandit y leer su JSON, (2) convertir los resultados a `Finding`, (3) armar el motor y probarlo de punta a punta.
- **Código / Arquitectura generada:** `backend/app/engines/sast/`: `bandit.py` ejecuta `python -m bandit -r . -f json` como subproceso con el repo como directorio de trabajo (rutas relativas), límite de 50 s y exclusión de `node_modules`, `.venv`, `dist`, etc.; ante timeout, código de salida inesperado o salida inválida lanza `BanditError` para que el orquestador lo registre y siga. `findings.py` mapea severidad de Bandit a la escala unificada, sube a `high` eval, exec e inyección SQL, baja un nivel si la confianza es baja, agrega CWE y títulos en español. `engine.py` expone `SastEngine` (`name = "sast"`). Reglas con prefijo `sast.bandit.<id>`. 26 tests en `test_sast_bandit.py`, `test_sast_findings.py` y `test_sast_engine.py`.
- **Validación y Corrección Humana:** Revisé la salida real de Bandit antes de mapearla. Se detectó que la opción `-x node_modules` no excluía nada y se cambió por patrones `*/node_modules/*`, verificado con un test. Siguiendo lo que se encontró en el motor post-cuántico: se descartan enlaces simbólicos y archivos fuera del repo (un repo malicioso podría filtrar archivos del servidor en el snippet) y se enmascaran todos los textos del snippet, porque Bandit incluye líneas vecinas que pueden tener secretos; el costo es que en la SQL armada no se ve la consulta, pero sí la línea. En Windows Bandit usa `\` como separador: se normaliza para que funcione igual en Linux. Semgrep (JavaScript) queda pendiente hasta medir si entra en los 512 MB del plan free de Render. Pendiente: agregar `bandit` a las dependencias del scan-worker.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(sast): motor SAST con Bandit

### [2026-11-03] Base del frontend y Dashboard general (Módulo B)

- **Problema abordado:** Entregar la base compartida del frontend (estructura, ruteo, layout con menú lateral, login con Clerk/GitHub, cliente de la API, tipos del contrato y componentes comunes) para que los demás módulos construyan sus vistas encima, y la pantalla del Dashboard general con Risk Score, nota A–F, distribución por motor y severidad, accesos a cada vista y triage de hallazgos.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), con las skills impeccable (contexto de producto y dirección visual), gsap-react, make-interfaces-feel-better y las recetas de transitions.dev. Le pedí implementar exclusivamente el frontend siguiendo la sección del Módulo B del plan de desarrollo, con commits semánticos por componente. Elegí la dirección visual entre las opciones que propuso ("Cartel de inspección A–F") y definí que el usuario principal es el líder técnico y que la demo tiene que priorizar claridad.
- **Código / Arquitectura generada:** `frontend/` con React 19 + Vite + TypeScript + Tailwind 4. `types/Finding.ts` copia `Severity` y `Finding` de `base.py` y agrega lo que suma la API (`id`, `status`, `fingerprint`, `triage`). `lib/api.ts` centraliza la URL, el JWT de Clerk y los errores de FastAPI. `lib/risk.ts` implementa los pesos y la fórmula del Risk Score de la sección 5. Componentes comunes: `SeverityBadge`, `FindingCard`, `FindingsTable` (filtros por estado, severidad, motor y texto), `CodeSnippet`, `EmptyState`, `Loader`/`Skeleton`, `ScanProgress` con `useScanPolling`, `StatusStamp`, `FindingStatusActions` y toasts con "Deshacer". El dashboard usa `mock.json` con las fallas plantadas del repo de demo y una fuente de datos que simula un escaneo completo cuando no hay API.
- **Validación y Corrección Humana:** Verifiqué que los tipos coincidan campo por campo con `base.py` y que el Risk Score de los mocks dé lo esperado a mano (penalización 66,5 → 33,5, nota F; al resolver dos críticos pasa a 53,5, nota D). `tsc -b`, `npm run lint` y `npm run build` sin errores. Revisé capturas en 1440 px y 390 px: se corrigió un desborde horizontal en mobile (la tabla por motor ensanchaba la grilla) y el orden de las filas de hallazgos en mobile. Se dividió el bundle en chunks (React, Clerk, GSAP) porque superaba los 500 kB. Decisiones y límites aceptados: sin `VITE_CLERK_PUBLISHABLE_KEY` la app corre en modo demo sin login; el Risk Score se recalcula en el cliente para que la nota cambie al instante, con la misma fórmula que usará el orquestador; los tipos de `Scan`, `Repository` y los campos extra de `Finding` son provisorios hasta que el Módulo A publique sus modelos; el dashboard muestra el primer repositorio conectado (todavía no hay selector). Quedan para otro PR el deploy en Cloudflare Pages, `render.yaml`, `wrangler.toml` y la CI.
- **Responsable:** Matías Balda
- **PR:** #14

### [2026-11-06] Motor de Secretos (secrets/engine.py)

- **Problema abordado:** Detectar secretos hardcodeados mediante expresiones regulares (AWS, GitHub, Slack, etc.) y alta entropía de Shannon, garantizando que el valor expuesto no quede en texto plano dentro del hallazgo final ni se dupliquen puntajes.
- **Prompt / Herramienta utilizada:** Claude Opus, revisión asistida para resolver issues de un Code Review cruzado (enmascaramiento global por línea, deduplicación de tokens conocidos frente a entropía genérica y soporte de formatos sin comillas como `.env`).
- **Código / Arquitectura generada:** `SecretsEngine` lee archivos no excluidos línea por línea. Ejecuta 5 patrones específicos y un patrón genérico (`GENERIC_VAR_REGEX`) que soporta variables con guiones bajos y formatos de asignación diversos (`=`, `:`, con/sin comillas). Se utiliza una lista temporal de secretos por línea para aplicar el reemplazo `***` de forma global antes de instanciar los objetos `Finding`.
- **Validación y Corrección Humana:** Se identificó mediante pruebas que un token de GitHub asignado a una variable llamada `GITHUB_TOKEN` era reportado dos veces (por regex de GitHub y por entropía). Se corrigió agregando validación de deduplicación. Además, se ajustó el regex genérico para que soporte sintaxis de variables como `secret_value` y archivos sin comillas como `.env` o `.yaml`.
- **Responsable:** Alvaro Marini / Valentina Pértile de la Vega (Review)
- **PR:** #15

### [2026-11-06] Regex genérico del motor de secretos (secrets/engine.py)

- **Problema abordado:** El regex genérico de `SecretsEngine` tardaba un tiempo cuadrático en líneas largas (14 s con 20 000 caracteres alfanuméricos, y sin terminar en 45 s con 50 000), lo que permitía colgar el motor con un repo ajeno. Además marcaba como secreto crítico URLs, código sin espacios y tipos de TypeScript, y si el secreto tenía `}` o `]` enmascaraba solo hasta ese carácter.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), durante la revisión cruzada del PR: le pedí revisar los cambios de Alvaro y aplicar las correcciones en el PR.
- **Código / Arquitectura generada:** `GENERIC_VAR_REGEX` con cuantificadores acotados y tres alternativas para el valor: entre comillas simples, entre comillas dobles (se toma entero) o sin comillas (solo caracteres propios de una credencial). `match.group(1)` pasa a `match.group(match.lastindex)`. Tests nuevos para línea larga, URLs y código, y secretos con `}` o `]`.
- **Validación y Corrección Humana:** Detecté el problema durante la revisión cruzada del PR, comparando el regex nuevo con el anterior: 20 000 caracteres tardaban 14 s y con 50 000 no terminaba en 45 s, mientras que el anterior tardaba 0,016 s con 400 000. Antes de aplicar el arreglo se escribieron los tests y se comprobó que los 7 casos nuevos fallaran con el regex anterior; con el arreglo pasan los 13 del motor y la suite completa da 146 tests OK y 3 saltados. Con el regex acotado, el peor caso probado tardó 3,2 s con 3,9 MB. Revisé que siga detectando `.env`, YAML, JSON, diccionarios y variables como `secret_value`. Limitaciones aceptadas para el MVP: no se detectan secretos en hexadecimal (su entropía máxima es 4,0 y el umbral del plan es 4,5), ni `github_pat_...`, ni `BEGIN ENCRYPTED PRIVATE KEY`, y `pnpm-lock.yaml` se sigue escaneando. Un valor sin comillas con caracteres fuera del conjunto permitido, como `$` o `!`, se corta en ese carácter: si la parte anterior no llega a 20 caracteres no se detecta, y si llega, el resto queda visible en el snippet. Pendiente de revisión por Alvaro.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #15

### [2026-11-06] Regla por vulnerabilidad en el motor SCA (engines/sca)

- **Problema abordado:** Todas las vulnerabilidades usaban la misma regla, y el fingerprint se calcula con motor + regla + archivo + línea. Al deduplicar, varias CVE de un mismo paquete se pisaban y quedaba una sola, por lo que se perdían hallazgos y el Risk Score salía mejor de lo real.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5). Lo detectó al comparar el mock del frontend con el motor durante la revisión de PRs, y le pedí corregirlo.
- **Código / Arquitectura generada:** `rule_id` pasa a ser `sca.osv.<id de la vulnerabilidad>` en `findings.py`. Test nuevo que pasa dos fallas del mismo paquete por `deduplicate`.
- **Validación y Corrección Humana:** Validación ejecutada con Claude Code a pedido de la responsable. El test nuevo falla sin el arreglo y pasa con él; la suite da 147 tests OK y 3 saltados (2 por falta de Bandit en el entorno local y 1 que usa internet, ejecutado aparte contra OSV real y aprobado). Comparación contra OSV real sobre el repo de demo: el motor devuelve 14 hallazgos; antes del arreglo quedaban 2 tras deduplicar (Risk Score 85) y ahora quedan los 14 (9 de lodash y 5 de requests, Risk Score 49). Limitación conocida: las versiones corregidas se informan por vulnerabilidad, no por paquete; en lodash van de 4.17.5 a 4.18.0. Revisé el cambio en `findings.py` y el test.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #19

### [2026-11-06] Reglas de Criptografía Clásica y CryptoEngine

- **Problema abordado:** Detectar algoritmos obsoletos (MD5, DES, RC4), AES-ECB, RSA débil y random inseguro. Evitar duplicación de reportes de RSA con la detección post-cuántica (PQC).
- **Prompt / Herramienta utilizada:** Claude Opus, refactorización a partir de un PR Review. Se integraron utilidades del módulo PQC (`_MaskStrings`, `_collect_imports`) para parseo y seguridad del código.
- **Código / Arquitectura generada:** `scan_classic` utiliza el módulo `ast` para Python y resolver alias de importación (detectando librerías `cryptography`, `Crypto`, `hashlib`), capturando excepciones de recursividad de AST. En JS emplea regex con enmascaramiento temporal de literales. En `crypto/__init__.py` se orquestaron ambos módulos, aplicando una deduplicación manual que prioriza el hallazgo "HIGH" clásico por sobre el "MEDIUM" cuántico cuando coinciden en la misma línea.
- **Validación y Corrección Humana:** Se validó que los literales de clave en `AES.new` ya no se filtren gracias a la reutilización de `_MaskStrings`. Se acotó el falso positivo de `random.choice` limitando su evaluación exclusivamente a cuando el resultado se asigna a variables de seguridad (password, token, secret).
- **Responsable:** Alvaro Marini / Valentina Pértile de la Vega (Review)
- **PR:** #16

### [2026-11-06] Modelos de Base de Datos y Conexión a Supabase

- **Problema abordado:** Diseñar el esquema relacional en SQLAlchemy respetando el modelo de datos (organizaciones, usuarios, repositorios, escaneos, hallazgos) y configurar la conexión para soportar el pooler transaccional de Supabase (PgBouncer).
- **Prompt / Herramienta utilizada:** Claude Opus, refinado mediante revisión cruzada en GitHub (PR Review) para ajustar compatibilidad con psycopg3 y formateo de Enums.
- **Código / Arquitectura generada:** `database.py` implementa `create_engine` con `pool_pre_ping=True` y `prepare_threshold=None` para evitar fallos de prepared statements en el puerto 6543 de Supabase. `models.py` define las tablas con cascadas, índices compuestos y tipos JSONB, almacenando los Enums por su valor en minúscula (`values_callable`).
- **Validación y Corrección Humana:** Se detectó en la revisión de código que los Enums de Python se guardaban en mayúscula (ej. `HIGH`), rompiendo el contrato que usa minúsculas (`high`); se corrigió con lambdas en SQLAlchemy. Además, se configuró explícitamente el `prepare_threshold` tras validar las limitaciones del pooler transaccional.
- **Responsable:** Alvaro Marini / Juan Ignacio Wilt (Review)
- **PR:** #18

### [2026-11-06] Dockerfile para Scan-Worker aislado

- **Problema abordado:** Crear un entorno de ejecución seguro y aislado para los motores de análisis, asegurando que se ejecuten sin privilegios de root, tengan Git instalado para clonar repositorios y no expongan el contenedor a fallos de seguridad por código de terceros.
- **Prompt / Herramienta utilizada:** Claude Opus, revisión humana (PR Review cruzado) para ajustes de contexto de build, variables de entorno de Redis y exclusión de archivos temporales.
- **Código / Arquitectura generada:** `backend/worker/Dockerfile` basado en `python:3.11-slim`. Se crea el usuario no privilegiado `qubitor`, se instala `git` y se define `/tmp/scans`. Se añadió un `backend/.dockerignore` para evitar que `.env` y `.venv` se filtren en la imagen. La conexión a la cola usa la variable `$REDIS_URL` inyectada dinámicamente en Render.
- **Validación y Corrección Humana:** Se corrigió el contexto de build en las instrucciones para construir correctamente la imagen. Se modificó el `CMD` fijo de localhost para que lea variables de entorno (`$REDIS_URL`), y se agregó el `.dockerignore` que faltaba para proteger secretos locales e ignorar carpetas pesadas.
- **Responsable:** Alvaro Marini / Juan Ignacio Wilt (Review)
- **PR:** #17

### [2026-11-06] Estados de escaneo y hallazgos info en el frontend (Módulo B)

- **Problema abordado:** Los estados de escaneo del frontend (`pending`/`done`) no coincidían con el enum `ScanStatus` de la API (`queued`, `running`, `completed`, `failed`): el dashboard no encontraba ningún escaneo terminado y el polling nunca se detenía. Además, los hallazgos `info` (inventario o buenas prácticas sin riesgo, como el CBOM) contaban como abiertos en «Penalizan X de Y» y ofrecían «Marcar resuelto» y «Falso positivo», aunque no son fallas reales.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5). Le pedí alinear todo el flujo de estado de escaneo con el enum oficial, mantener el polling solo mientras el estado sea `queued` o `running` y cortarlo en `completed` (resultados) o `failed` (error); que los `info` no penalicen ni muestren acciones de estado; sin modificar estilos y con commits separados según la convención del proyecto.
- **Código / Arquitectura generada:** `types/Scan.ts` con `ScanStatus = 'queued' | 'running' | 'completed' | 'failed'`, y los usos actualizados en `ScanProgress.tsx`, `dataSource.ts` (el último escaneo se busca con `completed`) y `mock.json`. `useScanPolling.ts` sigue consultando solo con los estados activos (`queued`, `running`) y se detiene ante cualquier otro, para no quedar consultando si llega un estado desconocido. `DashboardPage.tsx` trata por separado `completed`, `failed` y un estado inesperado. `lib/risk.ts` agrega `isInformational` (usa la severidad ajustada por la IA) y lo excluye de `countsTowardScore`. `stats.ts` deja los `info` fuera de «Penalizan» y de los «abiertos» por vista, pero los sigue mostrando en la fila «inventario» del desglose y en la matriz por motor. `FindingStatusActions` y `FindingsTable` no muestran acciones para los `info`. En un segundo paso, el campo `status` se mantiene en el dato (el modelo es del Módulo A y una columna nullable no aportaba nada), pero la UI lo ignora para los `info`: `FindingsTable` y `FindingCard` no muestran su sello de estado ni los tachan, y en la tabla solo aparecen en la pestaña «Todos», no en «Abiertos», «Resueltos» ni «Falsos positivos».
- **Validación y Corrección Humana:** `tsc -b` y `eslint` sin errores. Se buscaron con grep los literales `pending` y `done` de escaneo que quedaban en `src/`. Se confirmó que el peso de `info` ya era 0 en `lib/risk.ts` y en `backend/app/orchestrator/risk.py`, así que el puntaje no cambia; el cambio corrige el conteo y las acciones de la UI. Decisión: no ocultar los `info` del inventario, solo sacarlos de lo que penaliza. Se descartó mostrar una etiqueta o pestaña «Inventario» en la tabla. Limitaciones aceptadas: el primer commit no compila solo (el hook todavía usaba `done`), sí junto con el segundo. Pendiente: probar el polling en el navegador contra la API real.
- **Responsable:** Matías Balda
- **PR:** #21

### [2026-11-07] Vista «Dependencias» (frontend/src/features/dependencies)

- **Problema abordado:** Mostrar los hallazgos del motor SCA de forma accionable: qué paquetes tienen vulnerabilidades conocidas, a qué versión actualizar y con qué comando. Un paquete suele tener varias fallas corregidas en versiones distintas (lodash 4.17.4 tiene 9), así que listar cada CVE con su propio comando no resuelve el problema.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md` y los componentes compartidos del Módulo B.
- **Código / Arquitectura generada:** `packages.ts` agrupa los hallazgos por paquete y manifiesto, calcula la versión que corrige todas las fallas pendientes (descarta resueltas y falsos positivos), la peor severidad, el CVSS máximo y el comando `pip install` / `npm install`. `PackageTable.tsx` muestra cada paquete en un acordeón con sus CVE (enlace a NVD u OSV), CVSS y versión corregida, y botones para copiar el comando. `DependenciesPage.tsx` cubre carga, error, vacío y datos, y ofrece copiar todos los comandos juntos. `mock.json` sale de la salida real del motor sobre el repo de demo. En `App.tsx` se reemplazó el placeholder por la vista.
- **Validación y Corrección Humana:** `tsc -b`, `eslint` y `vite build` sin errores. Con un script se comprobó la agrupación con los datos del demo (lodash → 4.18.0, requests → 2.33.0) y casos borde: fallas resueltas, falsos positivos, fallas sin versión corregida y comparación de versiones. Revisé la vista en el navegador: el acordeón, los enlaces a los CVE y el botón de copiar funcionan; se corrigió la letra del rótulo «instalada» en pantallas angostas. Limitación: la vista usa datos de ejemplo hasta que la API tenga los endpoints de escaneos.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #23

### [2026-11-07] Vista «Preparación post-cuántica» (frontend/src/features/pqc)

- **Problema abordado:** Mostrar qué criptografía usa el repositorio (CBOM), qué parte rompería una computadora cuántica y en qué orden migrar a ML-KEM (FIPS 203) y ML-DSA (FIPS 204). Los hallazgos de `pqc.py` y de `classic.py` llegan sueltos: hay que clasificarlos por amenaza y agruparlos en pasos de migración.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md` y los componentes compartidos del Módulo B.
- **Código / Arquitectura generada:** `quantum.ts` clasifica cada hallazgo de criptografía en Shor, Grover, rota hoy o sin riesgo conocido (descarta falsos positivos; resueltos y descartados no cuentan, el inventario siempre cuenta), calcula el porcentaje vulnerable a Shor y arma la hoja de ruta: RSA < 2048, intercambio de claves a ML-KEM (primero, por «cosechar ahora, descifrar después»), claves RSA/EC de uso indefinido, firmas a ML-DSA y AES-128 a AES-256. `ExposureCard.tsx`, `MigrationRoadmap.tsx` y `CbomTable.tsx` muestran cada parte; `PqcPage.tsx` cubre carga, error, vacío y datos. `mock.json` sale de la salida real de CryptoEngine sobre el repo de demo. En `App.tsx` se reemplazó el placeholder por la vista. Agregado después: `quantum.ts` también clasifica las reglas de certificados de `certs.py` (PR #34): la clave RSA de menos de 2048 bits va al paso de RSA débil, las claves de certificados al paso de firmas, y la firma SHA-1 y el certificado vencido quedan como rotos hoy. Se sumó `tests/engines/test_repo_demo.py`, que clona el repo de demo y verifica los hallazgos post-cuánticos y de dependencias (con `QUBITOR_TESTS_RED=1`).
- **Validación y Corrección Humana:** Leí el código de `quantum.ts` y de los componentes. Corrí `pytest` en mi máquina (pasa, también el test del repo de demo con internet) y revisé la vista en el navegador: la exposición a Shor, la hoja de ruta y el inventario se ven bien con los datos del demo. Además, `tsc -b`, `eslint` y `vite build` dan sin errores, y con un script se comprobó la clasificación con los datos del demo (60 % vulnerable a Shor) y que un hallazgo resuelto deja de contar y un falso positivo desaparece. La clasificación de certificados (agregada después) se comprobó con un script y queda pendiente de mi revisión. Limitación: la vista usa datos de ejemplo hasta que la API tenga los endpoints de escaneos.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #24

### [2026-11-08] Botones de descarga del reporte y del CBOM (frontend/src/features/pqc)

- **Problema abordado:** El reporte y el CBOM de cada escaneo quedan en R2 (PR #30) y la API los entrega con URLs firmadas en `GET /scans/{id}/report` (rama `feature/scan-report`, Módulo A). Faltaba poder descargarlos desde las vistas.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md`.
- **Código / Arquitectura generada:** `ReportDownloadButton.tsx` pide las URLs recién al hacer clic, porque vencen a los pocos minutos, y abre la del archivo elegido; como R2 lo guarda como descarga, el navegador lo baja sin salir de la página. Si el escaneo no tiene el archivo o el almacenamiento no está disponible (503), muestra un aviso. Con datos de ejemplo el botón no aparece. La vista post-cuántica ofrece «Descargar CBOM (CycloneDX)» y la de Dependencias, «Descargar reporte». En el cliente compartido (`lib/api.ts` y `types/Scan.ts`, Módulo B) se sumó `getScanReport` con el formato de la respuesta de la API.
- **Validación y Corrección Humana:** *Pendiente.* Hecho hasta ahora: `tsc -b`, `eslint` y `vite build` sin errores. El formato de la respuesta se comparó con `ScanReportOut` del backend. Falta probarlo con la API desplegada y R2 configurado.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #24

### [2026-11-08] Firmas ECDSA en JavaScript y curvas Ed25519 / X25519 (crypto/pqc.py)

- **Problema abordado:** El detector post-cuántico no reconocía Ed25519, Ed448, X25519 ni X448, que son las curvas más usadas hoy y también las rompe Shor. Además, en JavaScript una clave EC que se usa para firmar (como la de `app/signing.js` del repo de demo) quedaba como «clave de uso indefinido», así que la hoja de ruta no la mandaba a ML-DSA.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** Regla nueva `crypto.pqc.eddsa` (medium) para Ed25519 y Ed448; X25519 y X448 se reportan como `crypto.pqc.ecdh`, porque son ECDH sobre otras curvas. En Python se detecta `Ed25519PrivateKey.generate()` y equivalentes de `cryptography`; en JavaScript, `generateKeyPair('ed25519' | 'ed448' | 'x25519' | 'x448')`. Si un archivo JavaScript genera una clave EC y además firma o verifica (`crypto.sign`, `crypto.verify`, `createSign`, `createVerify`), la clave se reporta como `crypto.pqc.ecdsa`. En la vista, `quantum.ts` manda `crypto.pqc.eddsa` al paso de firmas; el mock y el test del repo de demo se actualizaron.
- **Validación y Corrección Humana:** Leí los cambios en `pqc.py` y corrí `pytest` en mi máquina: pasan los 9 tests nuevos (positivos y negativos: cargar una clave Ed25519 sin generarla, firmar dentro de un comentario, firmar con una clave RSA) y el test del repo de demo con `QUBITOR_TESTS_RED=1`. En la vista revisé que la firma de `app/signing.js` ahora cae en el paso «Migrar las firmas a ML-DSA». `tsc -b`, `eslint` y `vite build` dan sin errores. Limitación: en JavaScript la firma se detecta por archivo; si la clave EC se genera en un archivo y se usa para firmar en otro, sigue apareciendo como clave de uso indefinido.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #29

### [PLANTILLA — completar en próximas entradas]

- **Problema abordado:**
- **Prompt / Herramienta utilizada:**
- **Código / Arquitectura generada:**
- **Validación y Corrección Humana:**
- **Responsable:**
- **PR:** #
