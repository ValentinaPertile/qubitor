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
- **Validación y Corrección Humana:** Revisé cada paso antes de su commit y pedí la explicación línea por línea de cada función hasta entenderla (recorrido de archivos, mapa de imports, resolución de nombres y reglas). Ejecuté la suite de tests (33 tests, todos pasan) y verifiqué que fallen al quitar una regla. Validé que los casos negativos eviten falsos positivos: comentarios y textos que mencionan algoritmos, objetos propios con nombres como `rsa` y librerías con nombres iguales. Dejé MD5 y SHA-1 fuera del módulo a propósito porque corresponden a criptografía clásica (Módulo C). Limitaciones identificadas y aceptadas para el MVP: el análisis no sigue variables (por ejemplo, `parametros.generate_private_key()` no se detecta, aunque sí el `dh.generate_parameters` que lo origina); con `algorithms.AES(clave)` no se puede determinar el tamaño de la clave, así que se registra como inventario sin tamaño; todavía no se cubren X25519/Ed25519 ni la carga de claves con `RSA.import_key`. La posible duplicación de RSA de menos de 2048 bits (como `high` en classic.py y como `medium` acá) quedó resuelta en `CryptoEngine`, que descarta el hallazgo post-cuántico cuando en la misma línea está el clásico; lo cubre `test_deduplicacion_rsa_cryptoengine` y se confirmó con el RSA de 1024 bits del repo de demo (20/11). En una revisión de seguridad que pedí antes de abrir el PR se encontraron y corrigieron dos problemas, verificados con archivos de prueba armados a propósito: (1) el detector seguía enlaces simbólicos, por lo que un repo malicioso podía hacerle leer archivos del servidor y filtrar su contenido en el reporte; ahora se saltean los enlaces y todo archivo que quede fuera del repo; (2) el `snippet` mostraba las claves escritas en el código (por ejemplo, `AES.new(b'clave')`), que se guardarían en la base y se enviarían a la IA, violando el contrato; ahora todo texto o bytes del snippet se reemplaza por `'***'` y el snippet se recorta a 200 caracteres. Se agregaron 4 tests que cubren estos casos.
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

### [2026-11-08] SAST de JavaScript con Semgrep

- **Problema abordado:** El SAST solo analizaba Python con Bandit. El plan pide Semgrep con reglas locales para JavaScript y, si no entra en los 512 MB del plan free de Render, documentar el límite.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** `app/engines/sast/rules/javascript.yml` con 7 reglas propias para JavaScript y TypeScript (eval, new Function, comando de shell y consulta SQL armados con datos variables, innerHTML/outerHTML, document.write y setTimeout/setInterval con texto), cada una con CWE. Son locales porque las del registro de Semgrep tienen licencia propia. `semgrep.py` ejecuta Semgrep y convierte su salida a `Finding`; `SastEngine` corre Bandit y Semgrep en paralelo y, si falla uno, devuelve los hallazgos del otro. Semgrep se instala solo en la imagen del worker y `SEMGREP_ENABLED=false` lo apaga. 15 tests nuevos.
- **Validación y Corrección Humana:** Semgrep no existe para Windows: los tests con Semgrep real se corrieron dentro de la imagen del worker (Linux), donde pasaron todos, incluidos los de symlinks que fallan en Windows. Medición con la imagen limitada a 512 MB y sin swap, escaneo completo con los 4 motores: OWASP Juice Shop (JavaScript grande) falló en el primer intento, porque Semgrep lanza un proceso por CPU (12) y, sumado a los demás motores, el contenedor llegó al tope. Con `--jobs 1` terminó bien dos veces seguidas en unos 28 s (11 hallazgos de Semgrep). Express y el propio repo de Qubitor también terminan bien. Conclusión para la defensa: entra en 512 MB, pero en repos grandes de JavaScript queda al límite; si en Render falla, Semgrep cae solo, el SAST sigue con Bandit y se puede apagar con la variable. La salida de Semgrep sin cuenta ya no incluye el código («requires login»), así que el snippet se lee del repo clonado y se enmascaran los textos, también los template literals. Se corrigió un caso en el que, sin Semgrep instalado, un error de Bandit se perdía en silencio.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(sast): SAST de JavaScript con Semgrep

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
### [2026-11-06] API base, cola de escaneos y scan-worker

- **Problema abordado:** Separar la API del escaneo: la API publica un trabajo y responde al instante, y un scan-worker independiente lo ejecuta, con reintentos y cola de errores (componente cloud del Módulo A). Además, dejar la imagen Docker del scan-worker en condiciones de conectarse a Upstash.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), de a un paso por commit: app FastAPI y configuración, cola con RQ, clonado, job de escaneo y corrección del Dockerfile (a partir de la rama de Alvaro).
- **Código / Arquitectura generada:** `app/main.py` (`/health`, CORS), `app/config.py`, `app/worker/queue.py` (`enqueue_scan`, 2 reintentos, 7 días en la cola de errores), `clone.py` (solo URLs públicas de GitHub, sin symlinks, corte a los 50 MB o 120 s), `job.py` (`run_scan`), `store.py` (interfaz `ScanStore`, con `LogScanStore` hasta que estén los modelos) y `run.py` (punto de entrada). `requirements.txt`, `requirements-dev.txt`, `.env.example` y `.dockerignore`. 40 casos de test nuevos.
- **Validación y Corrección Humana:** Probado de punta a punta con un worker real contra Upstash: el escaneo del propio repo terminó completo, y un repo inexistente y una URL de GitLab fallaron sin reintentos. Decisiones: reintentos sin intervalo, porque el scheduler de RQ consulta Redis todo el tiempo y gasta la cuota; JSON en lugar de pickle; un repo rechazado no se reintenta y una falla transitoria sí, marcando el escaneo como fallido recién en el último intento. Riesgo aceptado: RQ importa la función indicada en cada trabajo, así que quien tenga la URL de Redis podría ejecutar código en el worker; `REDIS_URL` debe tratarse como un secreto crítico. Durante la revisión, Valentina construyó la imagen Docker y la probó con el worker normal de Linux (con fork) contra un Redis en Docker: escaneó el repo de demo con los 4 motores (19 hallazgos, sin errores de motores), el contenedor corrió como `qubitor` con el código de la imagen como propiedad de root, encolar dos veces el mismo escaneo devolvió el mismo trabajo y el clon se borró al terminar. Limitación: todavía no hay endpoints de escaneo ni persistencia real.
- **Correcciones tras la revisión de la PR #20:** Valentina encontró que encolar dos veces el mismo escaneo lo ejecutaba dos veces: se había supuesto que RQ rechaza un `job_id` repetido, sin comprobarlo, y el test solo encolaba una vez. Ahora cada escaneo se marca con `SET NX` en Redis (atómico) y, si ya estaba, se devuelve el trabajo existente; se agregaron tests que encolan dos veces. También se registró `CryptoEngine` (la PR #16 se mergeó antes que esta), se sumaron `sqlalchemy` y `psycopg` a `requirements.txt` para los modelos de la PR #18, y al resolver el conflicto con la PR #17 se mantuvo el código de la imagen como propiedad de root (solo lectura para el worker).
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(worker): API base, cola de escaneos y scan-worker

### [2026-11-08] Límite de escaneos simultáneos por organización

- **Problema abordado:** El componente cloud del Módulo A pide un límite de concurrencia. Cada escaneo ocupa el worker hasta 5 minutos, así que una organización podía encolar escaneos de muchos repos y dejar esperando a las demás.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** En `POST /repositories/{id}/scans`, si la organización ya tiene `MAX_ACTIVE_SCANS_PER_ORG` escaneos en cola o en curso (por defecto 2), responde 429 con un mensaje para el usuario. Se cuentan con una sola consulta, sin los escaneos trabados. `max_active_scans_per_org()` en `app/config.py` ignora valores inválidos o no positivos. 10 tests nuevos.
- **Validación y Corrección Humana:** Probado contra Postgres 16: el tercer escaneo se rechaza, al terminar uno se libera el lugar, el límite es por organización, reescanear un repo que ya está en curso devuelve el mismo escaneo sin contar dos veces y un escaneo trabado no ocupa lugar. El plan habla de un límite «por plan», pero la base todavía no tiene planes de suscripción: por eso es una variable de entorno, que se puede reemplazar por un valor por organización cuando existan.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(api): limitar los escaneos simultáneos por organización

### [2026-11-07] Puntaje CVSS en el motor SCA (engines/sca/cvss.py)

- **Problema abordado:** OSV publica el vector CVSS pero no el puntaje, y la vista «Dependencias» tiene que mostrarlo. Además, sin la gravedad de GitHub, el motor asumía media aunque el vector permitiera calcularla.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), como parte del plan de las vistas del Módulo D.
- **Código / Arquitectura generada:** `cvss.py` calcula el puntaje base de CVSS 3.0 y 3.1 con las fórmulas de la especificación, sin dependencias nuevas, y devuelve None para CVSS 4.0, CVSS 2 o vectores inválidos. `findings.py` guarda el puntaje en `metadata["cvss"]`, prefiere el vector 3.x cuando hay varios y, si GitHub no informa la gravedad, la toma del CVSS con la escala del equipo (`severity_source: "cvss"`).
- **Validación y Corrección Humana:** Validación ejecutada con Claude Code. Los tests se escribieron antes que el código y comparan contra puntajes publicados por NVD (9,8, 9,9, 9,1, 7,5, 7,4 y 6,1), más casos de CVSS 4.0, CVSS 2 y vectores incompletos o inválidos; la suite completa da 171 tests OK y 3 saltados, y el test contra OSV real pasa. Sobre el repo de demo, 13 de las 14 vulnerabilidades tienen puntaje y los comparados con NVD coinciden; `CVE-2018-16487` de lodash no trae vector en OSV y queda sin puntaje. Limitación aceptada: CVSS 4.0 no se puntúa porque usa tablas en lugar de fórmulas. Revisé el cálculo en `cvss.py`, los cambios en `findings.py` y los tests.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #22

### [2026-11-07] Vista «Dependencias» (frontend/src/features/dependencies)

- **Problema abordado:** Mostrar los hallazgos del motor SCA de forma accionable: qué paquetes tienen vulnerabilidades conocidas, a qué versión actualizar y con qué comando. Un paquete suele tener varias fallas corregidas en versiones distintas (lodash 4.17.4 tiene 9), así que listar cada CVE con su propio comando no resuelve el problema.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md` y los componentes compartidos del Módulo B.
- **Código / Arquitectura generada:** `packages.ts` agrupa los hallazgos por paquete y manifiesto, calcula la versión que corrige todas las fallas pendientes (descarta resueltas y falsos positivos), la peor severidad, el CVSS máximo y el comando `pip install` / `npm install`. `PackageTable.tsx` muestra cada paquete en un acordeón con sus CVE (enlace a NVD u OSV), CVSS y versión corregida, y botones para copiar el comando. `DependenciesPage.tsx` cubre carga, error, vacío y datos, y ofrece copiar todos los comandos juntos. `mock.json` sale de la salida real del motor sobre el repo de demo. En `App.tsx` se reemplazó el placeholder por la vista.
- **Validación y Corrección Humana:** `tsc -b`, `eslint` y `vite build` sin errores. Con un script se comprobó la agrupación con los datos del demo (lodash → 4.18.0, requests → 2.33.0) y casos borde: fallas resueltas, falsos positivos, fallas sin versión corregida y comparación de versiones. Revisé la vista en el navegador: el acordeón, los enlaces a los CVE y el botón de copiar funcionan; se corrigió la letra del rótulo «instalada» en pantallas angostas. Limitación: la vista usa datos de ejemplo hasta que la API tenga los endpoints de escaneos.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #23

### [2026-11-08] CBOM en formato CycloneDX 1.6 (backend/app/storage/cyclonedx.py)

- **Problema abordado:** El inventario criptográfico (CBOM) tenía un formato propio. CycloneDX 1.6 es el estándar que incorpora activos criptográficos, así que el CBOM que se guarda en R2 se puede abrir con cualquier herramienta que lea CycloneDX.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** `cyclonedx.py` arma un componente `cryptographic-asset` por algoritmo, con su primitiva (`pke`, `signature`, `key-agree`, `hash`, `block-cipher`, etc.), sus funciones, el nivel de seguridad clásico y la categoría cuántica de NIST (0 para lo que rompe Shor y lo que ya está roto hoy), y cada lugar del código donde aparece (`evidence.occurrences` con archivo y línea). La severidad, la amenaza cuántica y las reglas de Qubitor van como `properties`. TLS sin validar se registra como protocolo. Agregado después: las reglas de certificados de `certs.py` (PR #34); la clave de cada certificado entra como algoritmo y cada certificado como componente `certificate` con sujeto, vencimiento y sus problemas (firma SHA-1, vencido) como `properties`. `reports.py` guarda este CBOM en R2 como `application/vnd.cyclonedx+json` y se descarga como `cbom.cdx.json`.
- **Validación y Corrección Humana:** Leí el código de `cyclonedx.py` y el cambio en `reports.py`, corrí `pytest` en mi máquina (también con `QUBITOR_TESTS_RED=1`, que valida contra el esquema oficial) y revisé el JSON de un CBOM generado. Los certificados (agregados después) tienen 4 tests más y entran en la validación contra el esquema oficial; también leí ese código y corrí sus tests. Cubren: 16 tests en `test_cyclonedx.py` (agrupación por algoritmo, niveles de seguridad, criptografía clásica, TLS como protocolo, regla desconocida, peor severidad, otros motores afuera) y 2 que validan contra el esquema JSON oficial de CycloneDX 1.6 con todas las reglas de `pqc.py` y `classic.py` (con `QUBITOR_TESTS_RED=1`, porque bajan el esquema). El CBOM del repo de demo también valida sin errores.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #31 (se mergeó a la rama del #30 cuando esa ya estaba en `main`; llega a `main` con el #36)

### [2026-11-08] Reporte del escaneo en PDF (backend/app/storage/pdf.py)

- **Problema abordado:** El plan pide guardar el reporte de cada escaneo en JSON y en PDF. El JSON sirve para herramientas; el PDF, para leerlo o compartirlo con alguien que no usa Qubitor.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** `pdf.py` arma el PDF con `reportlab` (licencia BSD), que se importa recién al generarlo para no ocupar memoria en el worker cuando no hace falta. Incluye repositorio, commit, fecha, Risk Score y nota, resumen por gravedad, motores con errores, los hallazgos de crítica a baja (hasta 300, con motor, CVE o CWE y archivo y línea) y el inventario criptográfico como lista de algoritmos. El texto se escapa para el formato de `reportlab` y lo que las fuentes estándar no pueden dibujar se reemplaza. `reports.py` lo guarda en R2 como `reports/<scan_id>/report.pdf`; si falla solo el PDF, el reporte JSON y el CBOM quedan guardados igual.
- **Validación y Corrección Humana:** Leí el código de `pdf.py` y el cambio en `reports.py`, corrí `pytest` en mi máquina y abrí el PDF generado con el repo de demo. Cubren: 6 tests en `test_pdf.py` que leen el texto del PDF generado con `pypdf` (resumen, acentos, orden por gravedad, sin problemas, motores con errores, límite de hallazgos, texto con marcas y caracteres raros) y 1 en `test_reports.py` (si falla el PDF, los JSON quedan). Se generó el PDF del repo de demo y se revisó cómo se ve. `pytest` pasa completo.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #36

### [2026-11-08] Certificados y claves versionados (engines/crypto/certs.py)

- **Problema abordado:** Además del código, los repos suelen tener certificados y claves commiteados (`.pem`, `.crt`, `.key`). Su algoritmo también lo puede romper Shor, y pueden tener problemas de hoy: claves RSA cortas, firmas con SHA-1 o certificados vencidos.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** `certs.py` recorre los archivos `.pem`, `.crt`, `.cer`, `.der` y `.key` (hasta 1 MB, con los mismos resguardos que `pqc.py` contra enlaces simbólicos y carpetas de dependencias), lee cada certificado o clave con la librería `cryptography`, incluidos los PEM con varios certificados y los certificados en DER, y reporta: `crypto.pqc.cert-quantum-vulnerable` (medium) para RSA, curva elíptica, DSA y Ed25519; `crypto.pqc.cert-weak-key` (high) para RSA de menos de 2048 bits, que reemplaza al anterior; `crypto.pqc.cert-weak-signature` (high) para firmas con SHA-1 o MD5; y `crypto.pqc.cert-expired` (medium) y `crypto.pqc.cert-expiring` (low, menos de 30 días). En `metadata` van el algoritmo, el tamaño de clave, el sujeto y el vencimiento. El hallazgo nunca copia el contenido del archivo. Las claves cifradas con contraseña y los archivos rotos se saltean. Que haya una clave privada commiteada lo sigue reportando el motor de secretos (Módulo C). `scan_pqc` llama a `scan_certs`, así no se toca `CryptoEngine`, que es compartido. En el repo de demo se plantó `certs/server.pem`, autofirmado con RSA de 1024 bits y SHA-1 y datos falsos. Después se sumaron los keystores PKCS#12 (`.p12`, `.pfx`) sin contraseña, con 3 tests; los que tienen contraseña se saltean, como las claves cifradas.
- **Validación y Corrección Humana:** Corrí `pytest` en mi máquina y probé el repo de demo: el certificado plantado da la clave RSA de 1024 bits y la firma SHA-1. Cubren: 16 tests en `test_certs.py` con certificados generados en el momento (RSA, curva elíptica, Ed25519, vencido, por vencer, cadena de dos certificados, DER, clave pública, clave privada sin copiar su contenido, clave cifrada, archivos rotos, otras extensiones y `node_modules`, archivo grande) y uno con un certificado RSA-1024 con SHA-1 generado con `openssl`, porque `cryptography` ya no firma con SHA-1. Un test contra el repo de demo real (con `QUBITOR_TESTS_RED=1`). `pytest` pasa completo.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #36 (iba en el #34; se juntó con el #36)

### [2026-11-08] Caché de OSV en Cloudflare Workers KV (engines/sca/cache.py)

- **Problema abordado:** Cada escaneo consultaba OSV por todas las dependencias y por el detalle de cada vulnerabilidad, aunque el mismo paquete y versión se hubiera consultado minutos antes. Las vulnerabilidades de una versión cambian poco de un día para otro, así que conviene cachearlas en una base clave-valor NoSQL (Cloudflare Workers KV, equivalente a DynamoDB en AWS).
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5). Se consultó la documentación de la API REST de Workers KV para confirmar la lectura de hasta 100 claves por pedido.
- **Código / Arquitectura generada:** `cache.py` tiene `KvCache`, un cliente mínimo de la API REST de KV que lee de a 100 claves (`bulk/get`) y escribe en lote (`bulk`) con vencimiento de 24 horas, y `CachedOsvClient`, que se usa igual que `OsvClient`: guarda por `ecosistema|paquete|versión` los ids de las vulnerabilidades (también la lista vacía, que es el caso más común) y por id el detalle de cada una. Un valor roto en la caché se vuelve a pedir a OSV; si KV falla, la caché se apaga para ese escaneo y se consulta OSV directo. Sin las variables `CF_*` el motor usa OSV directo, como antes. Para leer los detalles en lote, el pedido en paralelo pasó del motor a `OsvClient.get_vulns`.
- **Validación y Corrección Humana:** Corrí `pytest` en mi máquina, también con `QUBITOR_TESTS_RED=1` contra OSV real. Cubren: 13 tests en `test_sca_cache.py` con KV y OSV falsos (primera consulta y guardado, segunda sin OSV, solo las que faltan y en orden, otra versión es otra clave, detalles, valores rotos, KV caído, motor completo con dos escaneos, variables de entorno) y con la API de Cloudflare simulada (lotes de 100, token, vencimiento de 24 h, error de la API); 2 tests de `get_vulns`. `pytest` pasa completo, incluido el test contra OSV real. Probado con una cuenta real de Cloudflare KV desde la máquina local: se guardó y leyó una clave, y al escanear el repo de demo dos veces la segunda pasada respondió desde la caché (21 consultas a OSV en la primera, ninguna una vez propagadas las claves). KV tarda hasta 60 s en mostrar lo recién escrito, así que una pasada inmediata todavía puede consultar OSV. Falta cargar las variables en el scan-worker de Render.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #33
### [2026-11-08] Reportes y CBOM en Cloudflare R2 (backend/app/storage)

- **Problema abordado:** Guardar el resultado de cada escaneo fuera de la base, en un bucket S3-compatible (Cloudflare R2), para descargarlo desde la interfaz con URLs firmadas que vencen. Es el componente cloud del Módulo D (equivalente a S3 en AWS).
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** `storage/reports.py` arma dos JSON por escaneo: `report.json` (Risk Score, resumen por severidad y hallazgos) y `cbom.json` (solo criptografía, también la segura). `ReportStorage` los sube con `boto3` a `reports/<scan_id>/` como descarga y genera URLs firmadas de 10 minutos; si el archivo no existe devuelve None. `archive_scan` no lanza excepciones: si el bucket falla, el escaneo ya quedó guardado y solo se registra en el log. Sin las variables `R2_*` no hace nada y `boto3` no se carga. `R2_ENDPOINT` permite probar con otro servicio S3-compatible. El scan-worker (`worker/job.py`, Módulo A) llama a `archive_scan` después de guardar el escaneo.
- **Validación y Corrección Humana:** Corrí `pytest` en mi máquina: pasan los 15 tests con un bucket falso (contenido del reporte y del CBOM, URL firmada, archivo faltante, error del bucket, ids que arman otra ruta) y los 2 del worker (se guarda después del escaneo, no se guarda si falla). Lo probé con MinIO en Docker como bucket S3-compatible: el test contra el bucket real pasa, la URL vencida y la URL sin firma dan 403, y un escaneo completo del repo de demo dejó el reporte y el CBOM descargables. Cloudflare R2 pide una tarjeta para activarse, así que el bucket quedó en Supabase Storage, que es S3-compatible: se agregó la variable opcional `R2_REGION` (R2 usa `auto`; Supabase, la región del proyecto) con su test, y el resto del código no cambió. Probado contra el bucket real de Supabase desde la máquina local: el test contra el bucket real pasa, el reporte, el CBOM y el PDF se descargan con la URL firmada, sin firma da 403 y con la URL vencida da 400. Falta cargar las variables en Render.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #30
### [2026-11-08] Pantalla Historial (Módulo A)

- **Problema abordado:** La ruta `/history` mostraba un placeholder. El plan pide una pantalla con los escaneos del repositorio (fecha, estado, duración y nota A–F) y cómo cambia el Risk Score entre un escaneo y otro.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md`, la guía de `frontend/README.md` y el patrón de las vistas de Dependencias y Dashboard.
- **Código / Arquitectura generada:** `frontend/src/features/history/`: `dataSource.ts` (API o `mock.json`, como las demás vistas), `scans.ts` (cada escaneo completado se compara con el completado anterior, salteando fallidos y en curso) y `HistoryPage.tsx` con los cuatro estados (carga, error con reintento, sin repositorio y datos). Muestra el motivo de un escaneo fallido y los motores que no corrieron en uno parcial. Solo se tocó `App.tsx` para reemplazar el placeholder; los componentes y tipos compartidos no se modificaron.
- **Validación y Corrección Humana:** Lint y build en verde. Revisada en el navegador a 1440 px, 1024 px y 375 px, sin errores en consola. En la primera versión la tabla desbordaba a 1024 px (la página tenía scroll horizontal), porque el menú lateral ocupa lugar desde `lg`: se pasó la tabla en columnas a `xl` y debajo cada escaneo se muestra como ficha. También se probó contra la API real de las PRs de endpoints y guardado, con un Postgres local: el historial llegó del más nuevo al más viejo, con un escaneo fallido por la cola caída y uno parcial. Pendiente para la versión final: el gráfico de evolución con los hallazgos nuevos y resueltos.
- **Correcciones de la revisión antes del PR:** el `aria-label` sobre un `span` no se anuncia en lectores de pantalla: el guion de dato vacío ahora tiene texto oculto. El resumen dice «el escaneo más antiguo de la lista», porque el historial trae hasta 50, y contempla que el score no haya cambiado.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(history): pantalla Historial

### [2026-11-08] Evolución del Risk Score en el Historial

- **Problema abordado:** El plan pide que la pantalla «Historial» tenga un gráfico de evolución del Risk Score con los hallazgos nuevos y resueltos entre un escaneo y otro. La primera versión solo tenía la lista.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md` y una guía de visualización de datos (una sola serie sin leyenda, un solo eje, marcas finas, tooltip también con teclado).
- **Código / Arquitectura generada:** Backend: `GET /repositories/{id}/history` agrega `new_findings` y `resolved_findings` a cada escaneo completado, comparando sus fingerprints con los del completado anterior; no cuenta los hallazgos info (inventario) y saltea los fallidos. Frontend: `RiskTrendChart.tsx` en SVG propio, sin librerías nuevas: línea del Risk Score en el tiempo con la grilla en los cortes de las notas, solo el último valor etiquetado, crosshair y tooltip con nota, nuevos, resueltos y fecha, navegable con las flechas. La tabla suma la columna «Nuevos / resueltos». 3 tests nuevos de backend.
- **Validación y Corrección Humana:** Tests contra Postgres 16 para el conteo, incluidos los info y un fallido en el medio. Revisado en el navegador a 1440 px y 375 px, con el tooltip por mouse y por teclado, sin errores en consola. Los hallazgos nuevos y resueltos no se dibujan en un segundo eje (escala distinta): van en el tooltip y en la tabla. En el celular el gráfico no aparecía porque el ancho solo se medía con el primer aviso de `ResizeObserver`, que puede no llegar; ahora se mide al montarse.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(history): evolución del Risk Score

### [2026-11-08] Endpoints REST y autenticación con Clerk

- **Problema abordado:** El frontend tenía el cliente de la API listo pero no había endpoints: seguía con datos de ejemplo. Hacían falta los seis endpoints del plan y validar la sesión de Clerk en cada request, separando los datos por organización.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo los tipos del frontend (`types/Scan.ts`, `types/Finding.ts`) y el cliente `lib/api.ts`.
- **Código / Arquitectura generada:** `app/api/auth.py` valida el JWT (RS256, JWKS de Clerk con caché, vencimiento, emisor y `azp` contra los orígenes de CORS) y crea el usuario y su organización la primera vez; sin organización activa en Clerk se usa una personal. `app/api/routes.py`: `GET/POST /repositories`, `POST /repositories/{id}/scans` (crea el escaneo en cola y lo encola; si ya hay uno activo lo devuelve), `GET /repositories/{id}/history` (del más nuevo al más viejo), `GET /scans/{id}`, `GET /scans/{id}/findings` (por severidad efectiva) y `PATCH /findings/{id}` (recalcula el Risk Score con los abiertos que la IA no marcó como falso positivo, igual que el frontend). `app/api/schemas.py` con el formato de respuesta. 35 tests nuevos.
- **Validación y Corrección Humana:** Tests de autenticación con tokens firmados en el test: vencido, otro emisor, otra clave, HS256, otro `azp` y sin `sub`. Endpoints probados contra Postgres 16 en Docker, incluido que otra organización recibe 404 en todo y no puede modificar nada; se comprobó que el test falla si se quita el filtro por organización. Se verificó que el JWKS real de Clerk responde. También se probó la API con la sesión real de la base y la cola. Decisiones: un recurso de otra organización responde 404 y no 403, para no revelar que existe; `AUTH_DISABLED` solo para desarrollo local. Limitaciones: `progress` y `stage` del escaneo quedan en null mientras corre, porque el worker todavía no informa la etapa; un usuario pertenece a una sola organización a la vez.
- **Correcciones de la revisión antes del PR:** Si el worker se caía o el trabajo vencía, el escaneo quedaba en curso para siempre y el repo no se podía volver a escanear; ahora, pasados 30 minutos, se marca como fallido y se lanza uno nuevo. Además, `Acme/Demo` y `acme/demo` se conectaban como dos repos distintos. Ambos casos se reprodujeron con tests antes de corregirlos. Queda como limitación que dos pedidos simultáneos para el mismo repo pueden crear dos escaneos.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(api): endpoints REST y autenticación con Clerk
### [2026-11-08] Endpoint de descarga del reporte del escaneo

- **Problema abordado:** El worker guarda el reporte y el CBOM de cada escaneo en Cloudflare R2 (PR #30, Módulo D), pero el frontend no tenía cómo descargarlos. Hacía falta un endpoint que entregue URLs firmadas sin que nadie pueda pedir los archivos de otra organización.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), a pedido de Valentina, reutilizando `get_report_storage` y `signed_url` de su PR.
- **Código / Arquitectura generada:** `GET /scans/{id}/report` en `app/api/routes.py` devuelve `{report_url, cbom_url, expires_in}` (`ScanReportOut` en `schemas.py`). Usa el mismo `_get_scan` que los demás endpoints, así que un escaneo de otra organización responde 404 antes de consultar el bucket. Si un archivo no existe, su URL es `null`; si R2 no está configurado o no responde, 503. 6 tests nuevos.
- **Validación y Corrección Humana:** Probado contra Postgres 16 en Docker con la clase `ReportStorage` real y un cliente S3 falso. Se comprobó que el test de aislamiento falla si se quita el chequeo de organización. Se cubre también el caso en que crear el cliente de R2 falla (por ejemplo, un endpoint inválido), que en la PR #30 todavía puede lanzar desde `archive_scan`.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(api): endpoint para descargar el reporte del escaneo
### [2026-11-08] Guardado del escaneo en Postgres (SqlScanStore)

- **Problema abordado:** El scan-worker solo registraba los resultados en el log. Hacía falta guardar el estado del escaneo, el Risk Score y los hallazgos en Supabase, con los modelos de la PR #18, para que la API y el frontend muestren escaneos reales.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5): implementar la interfaz `ScanStore` con SQLAlchemy y probarla contra un Postgres real.
- **Código / Arquitectura generada:** `app/worker/sql_store.py` con `SqlScanStore`: `mark_running`, `save_result` y `mark_failed` actualizan la fila del escaneo que crea la API, cada uno en su propia transacción. `save_result` borra los hallazgos previos del escaneo antes de insertar, para que un reintento no los duplique. `get_store` usa la base si hay `DATABASE_URL` y, si no, sigue registrando en el log. 11 tests en `tests/worker/test_sql_store.py`, que corren con `QUBITOR_TEST_DATABASE_URL`.
- **Validación y Corrección Humana:** Probado contra Postgres 16 en Docker: estados del escaneo, hallazgos con su fingerprint, severidad y estado guardados por valor (`high`, `open`, `completed`), guardar dos veces sin duplicar, rollback completo si falla a mitad del guardado y el job completo de punta a punta escribiendo en la base. Para comprobar que los tests detectan errores, se quitó el borrado previo y el test de duplicados falló. Un escaneo inexistente o con id inválido se registra en el log y no se reintenta. Pendiente: la migración de Alembic y el RLS (Alvaro está levantando Supabase); los tests crean las tablas con `create_all`.
- **Correcciones de la revisión antes del PR:** Postgres rechaza el byte nulo en textos y JSONB, así que un archivo del repo con ese carácter hacía fallar el guardado de todo el escaneo (y se reintentaba en vano); se reprodujo con un test y ahora se quita antes de guardar. En `.env.example`, `DATABASE_URL` quedó comentada: con el valor de ejemplo el worker intentaba conectarse a una base inexistente.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(worker): guardar el escaneo y sus hallazgos en Postgres

### [2026-11-08] Progreso del escaneo por etapa

- **Problema abordado:** La barra de progreso del dashboard (`ScanProgress`, Módulo B) consulta `GET /scans/{id}` cada 1,5 s y espera `stage` y `progress`, pero el worker no informaba en qué etapa estaba: la barra mostraba «en curso» sin porcentaje.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** `app/worker/progress.py`: `report_stage` guarda la etapa y su porcentaje en los metadatos del trabajo de RQ, y `read_progress` los lee. `analyze_repository` recibe un `on_stage` opcional y avisa motores y normalización; el job avisa clonado, triage (antes de `apply_ai`, que también recalcula el score) y guardado. `GET /scans/{id}` consulta Redis solo si el escaneo está en curso. Las etapas son las mismas que `SCAN_STAGES` del frontend. La conexión a Redis se reutiliza por proceso. 10 tests nuevos.
- **Validación y Corrección Humana:** Se guardó en Redis y no en la base porque son datos de vida corta que cambian varias veces por escaneo, y así no hace falta tocar los modelos ni la migración. Un test recorre un escaneo real en la cola (Redis falso) y comprueba lo que la API lee en cada etapa. Si Redis no responde o el trabajo venció, el escaneo sigue y la barra queda sin porcentaje. Sin conexión reutilizada, cada consulta del frontend abría una conexión TLS nueva con Upstash.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat(worker): progreso del escaneo por etapa

### [2026-11-07] Vista «Preparación post-cuántica» (frontend/src/features/pqc)

- **Problema abordado:** Mostrar qué criptografía usa el repositorio (CBOM), qué parte rompería una computadora cuántica y en qué orden migrar a ML-KEM (FIPS 203) y ML-DSA (FIPS 204). Los hallazgos de `pqc.py` y de `classic.py` llegan sueltos: hay que clasificarlos por amenaza y agruparlos en pasos de migración.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md` y los componentes compartidos del Módulo B.
- **Código / Arquitectura generada:** `quantum.ts` clasifica cada hallazgo de criptografía en Shor, Grover, rota hoy o sin riesgo conocido (descarta falsos positivos; resueltos y descartados no cuentan, el inventario siempre cuenta), calcula el porcentaje vulnerable a Shor y arma la hoja de ruta: RSA < 2048, intercambio de claves a ML-KEM (primero, por «cosechar ahora, descifrar después»), claves RSA/EC de uso indefinido, firmas a ML-DSA y AES-128 a AES-256. `ExposureCard.tsx`, `MigrationRoadmap.tsx` y `CbomTable.tsx` muestran cada parte; `PqcPage.tsx` cubre carga, error, vacío y datos. `mock.json` sale de la salida real de CryptoEngine sobre el repo de demo. En `App.tsx` se reemplazó el placeholder por la vista. Agregado después, en el PR #37: `quantum.ts` también clasifica las reglas de certificados de `certs.py` (PR #36): la clave RSA de menos de 2048 bits va al paso de RSA débil, las claves de certificados al paso de firmas, y la firma SHA-1 y el certificado vencido quedan como rotos hoy. Se sumó `tests/engines/test_repo_demo.py`, que clona el repo de demo y verifica los hallazgos post-cuánticos y de dependencias (con `QUBITOR_TESTS_RED=1`).
- **Validación y Corrección Humana:** Leí el código de `quantum.ts` y de los componentes. Corrí `pytest` en mi máquina (pasa, también el test del repo de demo con internet) y revisé la vista en el navegador: la exposición a Shor, la hoja de ruta y el inventario se ven bien con los datos del demo. Además, `tsc -b`, `eslint` y `vite build` dan sin errores, y con un script se comprobó la clasificación con los datos del demo (60 % vulnerable a Shor) y que un hallazgo resuelto deja de contar y un falso positivo desaparece. La clasificación de certificados (agregada después) se comprobó con un script y leí su código. Limitación: la vista usa datos de ejemplo hasta que la API tenga los endpoints de escaneos.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #24

### [2026-11-08] Integración con GitHub: repos del usuario, conexión y clonado de privados (Módulo E)

- **Problema abordado:** Hasta ahora solo se podía pegar la URL de un repo público. Hacía falta listar los repos de la cuenta de GitHub del usuario, conectar uno validándolo contra GitHub y clonar repos privados, sin exponer el token OAuth de GitHub ni confundirlo con el JWT de sesión de Clerk.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo el plan de la sección 4 (Módulo E) y las correcciones de seguridad de la Fase 1 (SEC-02 y SEC-09).
- **Código / Arquitectura generada:**
  - `app/integrations/github/`:
    - `clerk.py`: token OAuth de GitHub desde la Backend API de Clerk;
    - `client.py`: cliente de la API de GitHub con paginación por cabecera `Link` y errores propios;
    - `routes.py`: `GET` y `POST /github/repositories`;
    - `tokens.py`: el worker resuelve el token de quien conectó un repo privado;
    - `settings.py` y `errors.py`.
  - `app/worker/clone.py`: validación con `fullmatch`, entorno mínimo para Git y token opcional como cabecera HTTP por `GIT_CONFIG_*`.
  - Migración `9c2f1a7d3b10`: `repositories.is_private` y `repositories.connected_by_user_id`.
  - `job.py` pide el token antes de clonar.
- **Validación y Corrección Humana:**
  - Tests con GitHub y Clerk simulados, más los endpoints y la resolución del token contra Postgres 17:
    - paginación, errores 401/403/404/429/500 y nombres inválidos sin llamar a GitHub;
    - repos de más de 50 MB, privados no habilitados y sin permiso de lectura;
    - aislamiento entre organizaciones, y que ninguna respuesta incluya el token.
  - Se comprobó que Git no recibe `DATABASE_URL`, `REDIS_URL` ni `CLERK_SECRET_KEY`, y que el token no aparece en los argumentos del proceso.
  - Con red: el clonado real de `octocat/Hello-World` funciona con el entorno mínimo; con un token inválido el error no lo filtra y no queda escrito en disco.
  - La migración se probó con upgrade, downgrade y upgrade, y `alembic check` no encuentra diferencias.
  - Se corrigió durante el desarrollo:
    - importar la configuración desde `routes.py` hacía que el worker sin `DATABASE_URL` no arrancara; se movió a `settings.py` y se agregó un test que importa el job sin base;
    - los clonados falsos de los tests del Módulo A no aceptaban el parámetro `token`, así que el job solo lo pasa cuando hay uno.
  - Decisiones:
    - 409 en lugar de 401 para «GitHub no vinculado», porque el frontend trata el 401 como sesión vencida;
    - los repos privados quedan detrás de `GITHUB_PRIVATE_REPOS=false` hasta corregir la ejecución de Bandit (SEC-01), porque el worker necesitaría `CLERK_SECRET_KEY`.
  - Limitaciones: Clerk exige credenciales propias de GitHub para leer el token; el nombre del proveedor (`oauth_github`/`github`) se prueba en ese orden porque la documentación no es consistente.
- **Responsable:** Valentino Chiappini
- **PR:** feat(github): listar, conectar y clonar los repos de GitHub del usuario

### [2026-11-08] Triage de hallazgos con Gemini y resumen ejecutivo (Módulo E)

- **Problema abordado:** Los motores devuelven hallazgos crudos. Hacía falta que Gemini indique falsos positivos, severidad real y remediación por hallazgo, y un resumen ejecutivo del repo, sin enviar secretos ni archivos completos y sin que una falla de la IA haga perder hallazgos o frene el escaneo.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), con la skill `gemini-api-dev` para usar el SDK y los modelos vigentes (Interactions API, `google-genai`), siguiendo la sección 5 del plan (response_schema) y el riesgo de cuota de la sección 10.
- **Código / Arquitectura generada:**
  - `app/ai/`:
    - `masking.py`: segundo enmascarado antes de enviar;
    - `gemini.py`: cliente con salida estructurada, `store=False` y errores de cuota, caída y respuesta inválida;
    - `triage.py`: lotes de 15, tope de 60, validación por fingerprint, caché por contenido y límites de seguridad;
    - `cache.py`: reutiliza evaluaciones del mismo repo desde la base;
    - `summary.py`: resumen con Gemini o heurístico;
    - `pipeline.py`: `apply_ai`, que no lanza;
    - `routes.py`: `GET /scans/{id}/summary`.
  - Integración en archivos del Módulo A: `ScanResult` suma `triage` y `summary` con valores por defecto, `SqlScanStore` guarda `findings.ai_*` y `scans.ai_summary`, y `job.py` llama a `apply_ai`. Migración `b41d7e2a9c55`.
- **Validación y Corrección Humana:**
  - Tests con Gemini simulado (y con Postgres 17 para caché, guardado y endpoint):
    - lotes, tope y prioridad;
    - secretos que no salen y fragmentos recortados a 5 líneas;
    - respuestas inválidas y fingerprints ajenos o repetidos;
    - cuota agotada, dos errores seguidos y límite de tiempo;
    - caché por contenido, sin compartirse entre organizaciones;
    - score recalculado y job completo con Gemini caído.
  - Contra la API real se verificó que el SDK acepta los parámetros (con una clave inválida responde `API_KEY_INVALID`) y que su error de cuota trae `status_code = 429`.
  - Riesgo identificado y mitigado: **prompt injection** desde el código escaneado. Un comentario en el repo podría pedirle a la IA que marque su propio hallazgo como falso positivo y baje el Risk Score. Además de indicarle que trate el fragmento como datos, se fijaron límites: un secreto nunca es falso positivo ni baja de severidad, y nada baja más de dos niveles.
  - Se corrigió durante el desarrollo: los fixtures de los tests creaban las tablas antes de importar los modelos y el primer test fallaba si corría solo.
  - Decisiones:
    - caché en la base, en lugar de un servicio nuevo, porque reutiliza los escaneos del mismo repo;
    - resumen heurístico como fallback, como pedía el Checkpoint 1;
    - modelo por defecto `gemini-3.5-flash-lite` por la cuota gratuita.
  - Limitaciones: no se probó con una clave real de Gemini, y los hallazgos más allá del tope de 60 quedan sin triage.
- **Responsable:** Valentino Chiappini
- **PR:** feat(ia): triage de hallazgos con Gemini y resumen ejecutivo

### [2026-11-08] Escaneo en cada push: Worker de webhooks y endpoint interno (Módulo E)

- **Problema abordado:** Lanzar un escaneo automáticamente en cada push sin un servidor propio esperando eventos (equivalente a Lambda + API Gateway), verificando que el evento venga de GitHub y sin crear una cola paralela a la del Módulo A.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), con la skill `workers-best-practices` de Cloudflare (`wrangler.jsonc`, tipos generados, logs y traces, secretos y comparación en tiempo constante).
- **Código / Arquitectura generada:**
  - `infra/webhook-worker/`: verifica `X-Hub-Signature-256`, responde `ping`, filtra los push a la rama por defecto, deduplica por `X-GitHub-Delivery` en KV y reenvía firmado a la API.
  - `app/integrations/github/webhooks.py`: `POST /internal/github/push` verifica la firma HMAC con timestamp, deduplica con `SET NX` en Redis y encola con `enqueue_scan` del Módulo A, con el mismo criterio de «escaneo activo» que la API.
- **Validación y Corrección Humana:**
  - Decisión de arquitectura: la auditoría de la Fase 1 mostró que con `REDIS_URL` se puede encolar cualquier función de Python en el scan-worker, así que el Worker **no** publica directo en Redis. Llama a la API, que es la única dueña de la cola.
  - Pruebas del Worker: 24 tests con vitest (firmas válidas e inválidas, eventos ignorados, duplicados, API caída o con error, cuerpo de más de 2 MiB y JSON inválido) y `wrangler deploy --dry-run` sin errores.
  - Pruebas del endpoint: 22 tests contra Postgres 17 (firma vieja, otro secreto, cuerpo modificado, valores no canónicos, entregas repetidas, escaneo activo, cola caída y varias organizaciones con el mismo repo).
  - La compatibilidad de la firma entre TypeScript y Python se fijó con un vector calculado en Python dentro de los tests del Worker.
  - Se corrigió durante el desarrollo: el endpoint limpiaba con `strip()` una URL con salto de línea y la aceptaba; ahora rechaza todo valor no canónico.
  - Limitaciones: no se desplegó el Worker ni se configuró un webhook real; KV es eventualmente consistente, por eso la API deduplica también.
- **Responsable:** Valentino Chiappini
- **PR:** feat(cloud): escaneo automático en cada push con un Worker de webhooks

### [2026-11-08] Pantalla «Conectar repositorio» y tests del frontend (Módulo E)

- **Problema abordado:** La ruta `/connect` era un placeholder. Hacía falta listar y buscar los repos de GitHub del usuario, conectar uno y lanzar su primer escaneo, y poder pegar la URL de un repo público. El frontend tampoco tenía ningún test.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md` (hojas, botones primario y secundario, inputs, cuatro estados) y los componentes compartidos del Módulo B, con la skill `vercel-react-best-practices`.
- **Código / Arquitectura generada:**
  - `features/connect/`:
    - `ConnectPage.tsx`: lista con búsqueda, «Cargar más», «Conectar y escanear» con `ScanProgress` y `useScanPolling`, y formulario de URL;
    - `dataSource.ts`: API o mocks;
    - `search.ts` y `types.ts`;
    - `mock.json`.
  - Vitest con jsdom y Testing Library (`vitest.config.ts`, `src/test/setup.ts`, `npm test`).
  - `lib/api.ts` exporta `request`, y `App.tsx` publica la ruta.
- **Validación y Corrección Humana:**
  - 27 tests:
    - búsqueda sin tildes ni mayúsculas;
    - validación de la URL, igual a la del backend;
    - paginación y conexión con escaneo;
    - error 409 de GitHub no vinculado, error de la API y toast ante una conexión fallida.
  - `eslint`, `tsc -b` y `vite build` sin errores; `npm audit --omit=dev` sin vulnerabilidades.
  - Se corrigió durante el desarrollo: el texto de ayuda del campo de URL estaba dentro del `<label>` y pasaba a formar parte del nombre accesible del input; ahora está afuera y se asocia con `aria-describedby`.
  - Decisión: la búsqueda filtra los repos ya cargados, porque la API de GitHub `/user/repos` no busca; si no hay resultados y quedan páginas, la pantalla lo avisa.
  - Limitación: no se revisó en un navegador real, solo con Testing Library en jsdom.
- **Responsable:** Valentino Chiappini
- **PR:** feat(connect): pantalla Conectar repositorio

### [2026-11-08] Panel de remediación y tarjeta de resumen ejecutivo (Módulo E)

- **Problema abordado:** Mostrar la evaluación de la IA en todas las vistas de hallazgos sin que cada módulo la reimplemente, y presentar el resumen ejecutivo del escaneo arriba del dashboard general sin rediseñar el trabajo del Módulo B.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md` y los componentes compartidos.
- **Código / Arquitectura generada:**
  - `features/ai/`:
    - `AiTriagePanel.tsx`: falso positivo, cambio de severidad, explicación, remediación en pasos y aviso de IA;
    - `remediation.ts`;
    - `ExecutiveSummaryCard.tsx`, `summaryData.ts`, `types.ts` y `mock.json`.
  - Cambios mínimos en archivos compartidos:
    - `FindingCard` usa el panel, así lo heredan las vistas de C y D;
    - `DashboardPage` agrega la tarjeta antes de la nota.
- **Validación y Corrección Humana:**
  - 14 tests nuevos (41 en total del frontend):
    - pasos numerados o con guiones;
    - falso positivo, cambio de severidad y sin triage;
    - texto de la IA escapado (un `<img onerror>` no se renderiza);
    - tarjeta con IA, heurística, cuota agotada, sin resumen y con error;
    - dashboard completo con la tarjeta integrada.
  - `eslint`, `tsc -b` y `vite build` sin errores.
  - Se corrigió durante el desarrollo: dentro de `FindingCard` el panel repetía la «Severidad del motor» que la tarjeta ya mostraba; se agregó `showSeverityChange` para ocultarla ahí.
  - Hubo que sumar un `matchMedia` mínimo al setup de los tests, porque jsdom no lo trae y el dashboard lo usa.
  - Limitación: no se revisó en un navegador real.
- **Responsable:** Valentino Chiappini
- **PR:** feat(ia): panel de remediación y resumen ejecutivo en el dashboard

### [2026-11-08] Botones de descarga del reporte y del CBOM (frontend/src/features/pqc)

- **Problema abordado:** El reporte y el CBOM de cada escaneo quedan en R2 (PR #30) y la API los entrega con URLs firmadas en `GET /scans/{id}/report` (rama `feature/scan-report`, Módulo A). Faltaba poder descargarlos desde las vistas.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md`.
- **Código / Arquitectura generada:** `ReportDownloadButton.tsx` pide las URLs recién al hacer clic, porque vencen a los pocos minutos, y abre la del archivo elegido; como R2 lo guarda como descarga, el navegador lo baja sin salir de la página. Si el escaneo no tiene el archivo o el almacenamiento no está disponible (503), muestra un aviso. Con datos de ejemplo el botón no aparece. La vista post-cuántica ofrece «Descargar CBOM (CycloneDX)» y la de Dependencias, «Descargar reporte (PDF)»; el PDF necesita que la API devuelva `pdf_url`. En el cliente compartido (`lib/api.ts` y `types/Scan.ts`, Módulo B) se sumó `getScanReport` con el formato de la respuesta de la API.
- **Validación y Corrección Humana:** Leí el código de `ReportDownloadButton.tsx` y de los cambios en `lib/api.ts`, `types/Scan.ts` y las páginas. Además, `tsc -b`, `eslint` y `vite build` sin errores. El formato de la respuesta se comparó con `ScanReportOut` del backend. Falta probarlo con la API desplegada y R2 configurado.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #37 (iba en el #24, pero quedó afuera del merge)

### [2026-11-08] Urgencia de migración con la desigualdad de Mosca (frontend/src/features/pqc)

- **Problema abordado:** El porcentaje vulnerable a Shor no dice cuán urgente es migrar. La desigualdad de Mosca lo responde: si los años que algo tiene que seguir protegido (X) más los que lleva migrar (Y) superan los que faltan para una computadora cuántica relevante (Z), ya está en riesgo hoy.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), siguiendo `DESIGN.md`.
- **Código / Arquitectura generada:** `mosca.ts` separa los usos activos vulnerables a Shor en dos grupos: datos cifrados e intercambio de claves (incluye las claves de uso indefinido, el caso más exigente) y firmas, cada uno con su propio X. Calcula X + Y, el margen Z − (X + Y) y qué hallazgos quedan en riesgo. Valores por defecto: 10 años para datos, 2 para firmas, 5 para migrar y Z hasta 2035, el año en que NIST deja de permitir RSA y curvas elípticas (NIST IR 8547). `MoscaCard.tsx` permite cambiar X, Y y Z y muestra el resultado de cada grupo; `CbomTable.tsx` marca los usos en riesgo. `quantum.ts` exporta `shorUse` para saber para qué se usa cada algoritmo.
- **Validación y Corrección Humana:** Revisé la tarjeta de Mosca en el navegador con los datos del demo. Además, `tsc -b`, `eslint` y `vite build` dan sin errores, y con un script se comprobó con los datos del demo: con los valores por defecto los tres usos de Shor quedan en riesgo (15 > 9); con X = 2 e Y = 3 quedan con margen; una firma ECDSA va al grupo de firmas; un hallazgo resuelto no cuenta; y los años fuera de rango o vacíos se acotan entre 0 y 50.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #32

### [2026-11-08] Firmas ECDSA en JavaScript y curvas Ed25519 / X25519 (crypto/pqc.py)

- **Problema abordado:** El detector post-cuántico no reconocía Ed25519, Ed448, X25519 ni X448, que son las curvas más usadas hoy y también las rompe Shor. Además, en JavaScript una clave EC que se usa para firmar (como la de `app/signing.js` del repo de demo) quedaba como «clave de uso indefinido», así que la hoja de ruta no la mandaba a ML-DSA.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** Regla nueva `crypto.pqc.eddsa` (medium) para Ed25519 y Ed448; X25519 y X448 se reportan como `crypto.pqc.ecdh`, porque son ECDH sobre otras curvas. En Python se detecta `Ed25519PrivateKey.generate()` y equivalentes de `cryptography`; en JavaScript, `generateKeyPair('ed25519' | 'ed448' | 'x25519' | 'x448')`. Si un archivo JavaScript genera una clave EC y además firma o verifica (`crypto.sign`, `crypto.verify`, `createSign`, `createVerify`), la clave se reporta como `crypto.pqc.ecdsa`. En la vista, `quantum.ts` manda `crypto.pqc.eddsa` al paso de firmas; el mock y el test del repo de demo se actualizaron.
- **Validación y Corrección Humana:** Leí los cambios en `pqc.py` y corrí `pytest` en mi máquina: pasan los 9 tests nuevos (positivos y negativos: cargar una clave Ed25519 sin generarla, firmar dentro de un comentario, firmar con una clave RSA) y el test del repo de demo con `QUBITOR_TESTS_RED=1`. En la vista revisé que la firma de `app/signing.js` ahora cae en el paso «Migrar las firmas a ML-DSA». `tsc -b`, `eslint` y `vite build` dan sin errores. Limitación: en JavaScript la firma se detecta por archivo; si la clave EC se genera en un archivo y se usa para firmar en otro, sigue apareciendo como clave de uso indefinido.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** #29 (se mergeó a la rama del #24 cuando esa ya estaba en `main`; llega a `main` con el #37)

### [2026-11-08] Worker de keep-alive para Render y workflow de CI (Módulo B)

- **Problema abordado:** La API en Render (plan free) se apaga tras 15 minutos sin tráfico y el primer pedido después tarda cerca de un minuto. Además, el repo no tenía CI, y `CONTRIBUTING.md` exige lint, build y tests en verde antes de mergear.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5). Le pasé las tareas con los límites: solo tocar `infra/worker-keepalive/`, `.github/workflows/ci.yml` y este archivo; URLs en `[vars]` y no en el código; el cron `*/10 0-1,11-23 * * *`; sin secretos; y que no despliegue ni haga push.
- **Código / Arquitectura generada:**
  - `infra/worker-keepalive/`: Cloudflare Worker con un handler `scheduled` que hace `GET /health` a cada URL de `TARGETS` en paralelo, con timeout (`TIMEOUT_MS`, 30 s por defecto). Loguea una línea por URL y no corta si una falla. Sin rutas HTTP (`workers_dev = false`), con Workers Logs activado y un README para desplegarlo y ver los logs.
  - `.github/workflows/ci.yml`: job de frontend (Node 22 con caché de npm, `npm ci`, `lint`, `build`) y de backend (Python 3.11 con caché de pip, `pytest -q`). Corre en `pull_request` y en push a `main` y `develop`, con `permissions: contents: read`. `concurrency` cancela las corridas viejas de un PR, pero no las de `main`/`develop`.
- **Validación y Corrección Humana:**
  - Worker: `tsc --noEmit` y `wrangler deploy --dry-run` sin errores. Lo probé con `wrangler dev --test-scheduled`: el disparo del cron devolvió `200` de `https://qubitor-api.onrender.com/health`.
  - CI en local: `npm ci`, `npm run lint` y `npm run build` sin errores. `pytest -q` (Python 3.12 en Windows, porque no tengo 3.11): 459 pasan y 115 se saltean. Fallan 3 tests de symlinks de `test_pqc.py` y `test_sca_manifests.py`, porque Windows pide un privilegio para crear enlaces; en Linux no pasa. Un cuarto test (`test_js_firmar_en_un_comentario_no_cambia_el_uso`) solo falla en Windows sin `PYTHONUTF8=1`, porque el archivo de prueba se escribe con la codificación del sistema. No se tocaron esos tests (son de otro módulo). La confirmación final es la primera corrida en GitHub.
  - Corrección de la cuenta de horas: las 750 h free de Render son por workspace y se comparten entre todos los web services. Con la ventana elegida, un servicio usa ~465 h/mes, pero dos usarían ~930 h. Quedó documentado en `wrangler.toml` que, si se suma el scan-worker, hay que achicar la ventana a ~12 h/día.
  - Corrección tras la primera corrida en GitHub: el job de backend terminó con exit code 2 y 45 errores de colección (`ModuleNotFoundError: No module named 'app'`). `pytest` a secas no agrega `backend/` al `sys.path` (en local andaba porque se corría con `python -m pytest`). Se cambió el paso a `python -m pytest -q`, sin tocar código del backend. Verificado en un contenedor `python:3.11` (Linux) con una copia limpia del repo: 463 pasan y 114 se saltean (Postgres, internet o bucket real).
- **Responsable:** Matías Balda
- **PR:** #50

### [2026-11-09] Bloqueo de Cloudflare a los pedidos del backend a la API de Clerk (Módulo E)

- **Problema abordado:** En producción, la pantalla «Tus repositorios de GitHub» mostraba «Clerk rechazó la clave secreta del backend», pero la clave no era el problema. `clerk.py` llamaba a la Backend API de Clerk con `urllib` sin header `User-Agent`, así que el pedido salía como `Python-urllib/3.11`. La API de Clerk está detrás de Cloudflare, que bloquea ese User-Agent con `403` y `error code: 1010`. Como el código daba el mismo mensaje para 401 y 403, el bloqueo parecía un problema de clave.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5). Le pasé la causa ya confirmada con los límites: agregar el `User-Agent` con el mismo criterio que `client.py`, separar los mensajes de 401 y 403 sin cambiar el resto del comportamiento, cubrirlo con tests usando el fixture `clerk_falso`, no tocar `engines/sca/` y no hacer push.
- **Código / Arquitectura generada:**
  - `backend/app/integrations/github/clerk.py`: `_request` manda `"User-Agent": "Qubitor"`, igual que el cliente de GitHub. El 401 sigue diciendo «Clerk rechazó la clave secreta del backend»; el 403 ahora dice «Clerk bloqueó el pedido del backend (403)».
  - `backend/tests/integrations/test_github_clerk.py`: un test que verifica el header (`Request.get_header` normaliza el nombre a `User-agent`) y otro que verifica que 401 y 403 den mensajes distintos y que ninguno incluya la clave.
- **Validación y Corrección Humana:**
  - Reproducción antes del cambio, con la misma clave y el mismo usuario: `curl -A "Python-urllib/3.11" ...` contra `oauth_access_tokens` devolvió `403` con `error code: 1010`; el mismo `curl` sin `-A` devolvió `200`. Eso descartó la clave y apuntó al User-Agent.
  - `python -m pytest -q` desde `backend/` (Python 3.12 en Windows, con `PYTHONUTF8=1`): 465 pasan y 115 se saltean. Pasan los 16 tests de `test_github_clerk.py`. Fallan los mismos 3 tests de symlinks de siempre (`test_pqc.py`, `test_sca_manifests.py`), que también fallan en `main` porque Windows pide un privilegio para crear enlaces.
  - Queda pendiente: `engines/sca/osv.py` y `engines/sca/cache.py` también llaman sin `User-Agent`. Hoy funcionan, así que no se tocaron.
- **Responsable:** Matías Balda
- **PR:** #51

### [2026-11-09] Carpeta de clones en Render

- **Problema abordado:** El primer escaneo real en Render (repo de demo) falló con `FileNotFoundError` sobre `/tmp/scans/scan-…`. Render arranca el contenedor con `/tmp` vacío, así que la carpeta que crea el Dockerfile no existe y ningún escaneo podía clonar. RQ lo reintentó dos veces en vano.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5), a partir del trabajo fallido que quedó en la cola de errores de Upstash.
- **Código / Arquitectura generada:** `_new_workdir` en `app/worker/job.py` crea `REPOS_DIR` si no existe antes de crear la carpeta temporal del clon. Además, eso ahora ocurre dentro del `try`: antes, si fallaba, el escaneo nunca se marcaba como fallido y quedaba «en curso» hasta que la API lo daba por trabado a los 30 minutos. 2 tests nuevos.
- **Validación y Corrección Humana:** Los dos tests fallan sin la corrección y pasan con ella. Se reprodujo la situación de Render con la imagen del worker, `/tmp` vacío (tmpfs) y 512 MB: el escaneo del repo de demo terminó completo (21 hallazgos, sin errores de motores), la carpeta se creó y el clon se borró al final.
- **Responsable:** Juan Ignacio Wilt
- **PR:** fix(worker): crear la carpeta de clones si no existe

### [2026-11-19] Organizaciones con varios miembros y roles

- **Problema abordado:** La versión final del plan pide organizaciones con varios miembros y roles. La API ya separaba los datos por organización, pero cada usuario tenía una sola organización y no había roles: cualquiera podía hacer todo.
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** Tabla `memberships` (usuario, organización, rol y última actividad) con su migración de Alembic, que carga las membresías de los usuarios existentes. `auth.py` lee el rol del token de Clerk en cada pedido (`org_role` del formato v1 u `o.rol` del v2): `org:admin` es admin y cualquier otro rol es member; sin organización activa, el usuario es admin de la suya personal. `require_admin` protege conectar repositorios (URL pública y GitHub); los member pueden ver, escanear y marcar hallazgos. `GET /me` (rol, organización y permisos) y `GET /organization/members` (miembros con rol y última actividad; nombre y foto pedidos a la API de Clerk en el momento). Pantalla «Organización» en el frontend con el rol, los permisos, los miembros y el `OrganizationSwitcher` de Clerk para crear organizaciones, invitar miembros y cambiar roles.
- **Validación y Corrección Humana:** Clerk queda como fuente de verdad de los roles: la API no tiene endpoints para cambiarlos, así que no hay dos lugares que se puedan contradecir, y un cambio de rol en Clerk se aplica en el próximo pedido. Un token con organización pero sin rol se toma como member, no como admin. La base no guarda nombres ni emails: se piden a Clerk solo para la lista de miembros, y si Clerk no responde la lista sale igual. 25 tests nuevos de backend contra Postgres 16 (roles de v1 y v2, 403 para member en los dos endpoints de conexión sin pedir el token de GitHub, cambio de rol, cambio de organización conservando las membresías y aislamiento entre organizaciones); se comprobó que fallan si se quita `require_admin`. La migración se probó subiendo con datos existentes y bajando. 3 tests nuevos del frontend y revisión en el navegador a 1440 y 375 px. Los tests existentes ahora usan tokens con rol admin, que es lo que suponían. Pendiente fuera del código: activar Organizations en el panel de Clerk para que aparezca el selector.
- **Responsable:** Juan Ignacio Wilt
- **PR:** feat: organizaciones con varios miembros y roles

### [2026-11-20] Fallas del Módulo C en el repo de demo y test de punta a punta

- **Problema abordado:** El repo de demo tenía solo las fallas del Módulo D, así que en la demo y la defensa SAST, secretos y criptografía clásica no mostraban nada. Faltaba además confirmar que el RSA de menos de 2048 bits no se reporte dos veces (clásica y post-cuántica).
- **Prompt / Herramienta utilizada:** Claude Code (Claude Opus 5.5).
- **Código / Arquitectura generada:** En `qubitor-demo-vulnerable`: `app/db.py` (SQL con f-string), `app/utils.py` (`eval`), `app/auth.py` (MD5 para contraseñas), `app/crypto_utils.py` (RSA de 1024 bits y AES-ECB), `config/settings.py` y `.env.example` (AWS key y token de GitHub inventados y visiblemente falsos). En `qubitor`: `test_repo_demo.py` suma el inventario del AES-ECB y un test de que el RSA de 1024 bits sale solo como `crypto.classic.rsa-weak-key`.
- **Validación y Corrección Humana:** Antes de plantar, revisé qué detecta cada motor del Módulo C (`classic.py`, el regex del motor de secretos y Bandit) para que cada falla tenga una forma que efectivamente se reconozca. Corrí los cuatro motores sobre el repo de demo en local y cada falla aparece donde corresponde: B608 en `app/db.py:8`, B307 en `app/utils.py:7`, `secrets.aws` y `secrets.github` como critical, `crypto.classic.weak-hash`, `rsa-weak-key` y `aes-ecb`. Confirmé que la duplicación de RSA < 2048 que había quedado pendiente en la entrada de `pqc.py` ya la resuelve `CryptoEngine`: el RSA de 1024 bits sale una sola vez, como `crypto.classic.rsa-weak-key` (high). El único hallazgo post-cuántico nuevo es el inventario del AES-ECB, sin tamaño de clave. Los tests del demo pasan contra la copia local y fallan contra el repo publicado hasta subir las fallas, como se esperaba. Las credenciales tienen el formato que pide el motor pero dicen FAKE y Demo en el valor. Decidí no plantar todavía el secreto en el historial de Git ni el Dockerfile y el nginx.conf, porque ningún motor los analiza: quedan para cuando el Módulo C sume esos motores. Las fallas las planté yo en lugar del Módulo C, con aviso al equipo, para llegar a la defensa con los cuatro motores mostrando resultados.
- **Responsable:** Valentina Pértile de la Vega
- **PR:** test(pqc): actualizar el test del repo de demo con las fallas del Módulo C

### [PLANTILLA — completar en próximas entradas]

- **Problema abordado:**
- **Prompt / Herramienta utilizada:**
- **Código / Arquitectura generada:**
- **Validación y Corrección Humana:**
- **Responsable:**
- **PR:** #
