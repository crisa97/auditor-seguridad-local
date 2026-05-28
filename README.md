# Auditor de Seguridad Local con IA

Analiza **cualquier proyecto de código fuente** en busca de vulnerabilidades de forma **100% local y privada**, combinando un LLM especializado en seguridad con RAG sobre datos reales del NVD, ExploitDB y OWASP Top 10 2025.

---

## Arquitectura (Hexagonal / Ports & Adapters)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INTERFACES (driven)                          │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │  analizador_cli  │  │  generar_apikey  │  │ validation_api    │  │
│  │  (argparse)      │  │  (argparse)      │  │  (FastAPI)        │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬──────────┘  │
└───────────┼──────────────────────┼─────────────────────┼─────────────┘
            │                      │                     │
┌───────────┼──────────────────────┼─────────────────────┼─────────────┐
│           ▼                      ▼                     ▼             │
│                     APPLICATION (casos de uso)                       │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │ AnalizarProyecto │  │ ValidarApiKey    │  │ ValidarAfirmacion │  │
│  │                  │  │ ValidarAfirmacion│  │ SincronizarNvd    │  │
│  └────────┬─────────┘  └────────┬─────────┘  │ IndexarExploitDb   │  │
│           │                     │             │ IndexarOwaspTop10  │  │
│           │                     │             │ Enrichir (RAG)     │  │
└───────────┼──────────────────────┼────────────┴───────────────────┘  │
            │                      │                                   │
┌───────────┼──────────────────────┼───────────────────────────────────┘
│           ▼                      ▼                                   │
│              PORTS (interfaces abstractas)                           │
│  ┌────────────────┐  ┌───────────────────┐  ┌──────────────────┐    │
│  │ ICveRepository  │  │ IApiKeyRepository  │  │ ILlmService      │    │
│  │ IHallazgoRepo   │  │ IConocimientoRepo  │  │ IEmbeddingService │   │
│  │ IAnalisisRepo   │  │                    │  │ IVectorStore     │    │
│  └────────┬────────┘  └────────┬──────────┘  │ IReportGenerator │    │
└───────────┼──────────────────────┼────────────┴──────────────────┘    │
            │                      │                                    │
┌───────────┼──────────────────────┼────────────────────────────────────┘
│           ▼                      ▼                                    │
│                     ADAPTERS (implementaciones)                       │
│  ┌────────────────┐  ┌───────────────────┐  ┌──────────────────┐     │
│  │ MongoCveRepo    │  │ PostgresApiKeyRepo│  │ OllamaLlmService  │    │
│  │ MongoExploit    │  │ PostgresConocim.  │  │ OllamaEmbedding   │    │
│  │ MongoOwaspTop10 │  │                   │  │ ChromaVectorStore │    │
│  │ MongoHallazgo   │  │                   │  │ PdfReportGenerator│    │
│  │ MongoAnalisis   │  │                   │  └──────────────────┘     │
│  └────────────────┘  └───────────────────┘                             │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Requisitos

- **Docker** y **Docker Compose**
- **Python 3.10+** (en el host para scripts CLI)
- **RAM**: 8 GB mínimos (codellama:7b) / 16 GB recomendados (deepseek-coder)

---

## Instalación rápida

```bash
# 1. Clonar
git clone <repo> && cd seguridad-local

# 2. Configurar variables de entorno
cp .env.example .env
nano .env   # ajustar contraseñas, hosts, etc.

# 3. Levantar infraestructura
docker compose up -d

# 4. Instalar dependencias Python
pip install -r requirements.txt

# 5. Sincronizar base NVD
python3 update_nvd_db.py
```

---

## Uso del analizador CLI

El CLI corre **desde la consola del host**, tanto si estás dentro de la misma red que los contenedores Docker como si accedes externamente (siempre que los puertos estén expuestos).

### Análisis directo

```bash
# Escanea un proyecto completo
python3 analizador_rag_cli.py /ruta/al/proyecto

# Con API key (para autenticación contra validation-service)
python3 analizador_rag_cli.py --api-key "sk-xxx" /ruta/al/proyecto

# Enviar resultados al servicio de validación
python3 analizador_rag_cli.py \
  --api-key "sk-xxx" \
  --enviar "http://localhost:8000" \
  /ruta/al/proyecto
```

### Modo cola (Celery)

Para análisis pesados sin bloquear la terminal:

```bash
# Encolar análisis
python3 analizador_rag_cli.py --queue /ruta/al/proyecto

# Consultar estado
python3 analizador_rag_cli.py --status <task_id>

# Listar análisis realizados
python3 analizador_rag_cli.py --list
```

### Resultados

El análisis genera dos archivos en `reportes/`:
- `informe_seguridad_<fecha>.txt`
- `informe_seguridad_<fecha>.pdf`

---

## Generación de API Keys

```bash
# Generar y almacenar en BD
python3 generar_apikey.py --cliente "Cliente ACME" --permisos "rag:leer" --dias 365

# Solo generar (sin BD)
python3 generar_apikey.py --cliente "Test" --solo-generar
```

Las API keys se almacenan como hash PBKDF2-SHA256 con 600k iteraciones.

---

## Módulo OWASP Top 10 2025

El proyecto incluye un indexador para el **OWASP Top 10 2025** que clona el repositorio oficial de GitHub y procesa los 16 documentos markdown de `2025/docs/en/`:

### Documentos indexados

| ID | Documento | Categoría |
|---|---|---|
| `0x00` → `0x03` | Introducción, About OWASP, Risk Methodology, AppSec Program | Contexto |
| `A01` → `A10` | Broken Access Control, Injection, Cryptographic Failures... | Riesgos #1–#10 |
| `X01` | Next Steps (Honorable Mentions: Vibe Coding, Memory Mgmt...) | Bonus |

```bash
# Indexar OWASP Top 10 en MongoDB + ChromaDB
python3 index_owasp_top10.py
```

### Endpoint de enriquecimiento RAG (`POST /api/v1/rag/enrichir`)

El endpoint unifica las 3 fuentes de conocimiento en una sola consulta:

```bash
curl -X POST http://localhost:8000/api/v1/rag/enrichir \
  -H "Content-Type: application/json" \
  -d '{
    "texto": "authentication bypass with JWT",
    "api_key": "token-interno",
    "max_cves": 3,
    "max_exploits": 2,
    "max_owasp": 2
  }'
```

Respuesta: contexto unificado con CVEs relevantes, exploits relacionados y documentación OWASP.

### Flujo de enriquecimiento automático (Open WebUI)

1. Usuario escribe en Open WebUI
2. `patches/openwebui_inject.py` intercepta `/api/chat/completions`
3. Extrae el texto de la consulta y llama al endpoint enrichir
4. Inyecta el contexto como mensaje `system` antes de `call_next()`
5. El LLM responde con conocimiento actualizado de vulnerabilidades reales

### Manejo de archivos binarios

`IndexarExploitDb._parse_files()` usa una whitelist de 84 extensiones de texto para ignorar archivos binarios (imágenes, PDFs, ejecutables). Adicionalmente, `OllamaEmbeddingService._clean_text()` detecta contenido binario por ratio de caracteres de control (>5%) y lo descarta automáticamente.

---

## Middleware de validación (anti-falsos positivos)

Servicio FastAPI que intercepta consultas a Open WebUI y valúa:

1. **API key** contra PostgreSQL (`api_keys`)
2. **Afirmaciones** contra conocimiento validado (`conocimiento_validado`)
3. Si hay falsos positivos conocidos → bloquea la respuesta
4. **Enriquecimiento RAG automático** — antes de responder, consulta ChromaDB (NVD + ExploitDB + OWASP Top 10) e inyecta contexto de vulnerabilidades relevantes como mensaje `system`

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Consultar con validación
curl -X POST http://localhost:8000/api/v1/rag/consultar \
  -H "Content-Type: application/json" \
  -d '{"texto": "consulta", "api_key": "sk-xxx"}'

# Enriquecimiento RAG directo
curl -X POST http://localhost:8000/api/v1/rag/enrichir \
  -H "Content-Type: application/json" \
  -d '{"texto": "SQL injection", "api_key": "token-interno", "max_cves": 3, "max_exploits": 3, "max_owasp": 3}'
```

Documentación interactiva: http://localhost:8000/api/v1/docs

### Variables de enriquecimiento RAG

| Variable | Default | Descripción |
|---|---|---|
| `RAG_AUTO_ENRICH` | `true` | Activa/desactiva el enriquecimiento automático desde Open WebUI |
| `RAG_MAX_CVES` | `5` | Máximo de CVEs a incluir por consulta |
| `RAG_MAX_EXPLOITS` | `5` | Máximo de exploits a incluir por consulta |
| `RAG_MAX_OWASP` | `3` | Máximo de documentos OWASP Top 10 a incluir por consulta |
| `ENRICH_TIMEOUT` | `120` | Timeout en segundos para la llamada de enriquecimiento |
| `ENRICH_INTERNAL_TOKEN` | — | Token interno para comunicación validation-service ↔ Open WebUI |

---

## Sincronización de bases de datos

```bash
# NVD (CVE de los últimos 90 días)
python3 update_nvd_db.py

# ExploitDB (filtra archivos binarios automáticamente)
python3 index_exploitdb.py

# OWASP Top 10 2025 (clona repo oficial + indexa 16 documentos)
python3 index_owasp_top10.py

# Forzar actualización NVD desde el CLI
python3 analizador_rag_cli.py --update-nvd /ruta/proyecto
```

---

## Pruebas

```bash
python3 -m pytest tests/ -v
```

---

## Embeddings e indexación

### Capa de sanitización (doble filtro)

Para evitar errores al enviar contenido binario al motor de embeddings:

1. **Whitelist de extensiones** (`IndexarExploitDb.TEXT_EXTENSIONS`): solo procesa archivos con 84 extensiones de código/texto conocidas
2. **Detección de contenido binario** (`OllamaEmbeddingService._is_binary`): descarta textos con >5% de caracteres de control o replacement chars
3. **Auto-split recursivo**: cuando un batch excede el límite de contexto de `nomic-embed-text` (8192 tokens), se divide recursivamente hasta llegar a textos individuales
4. **Truncado progresivo**: texto individual demasiado largo se trunca a 4000→3000→2000→1000→500 caracteres hasta que quepa

---

## Patrones de diseño aplicados

| Patrón | Implementación |
|---|---|---|---|
| **Arquitectura Hexagonal** | Capas domain → ports → adapters → application → interfaces |
| **Repository** | 7 interfaces (`ICveRepository`, `IExploitRepository`, `IOwaspTop10Repository`, etc.) con implementaciones MongoDB/PostgreSQL |
| **Service Layer** | Casos de uso: `AnalizarProyecto`, `ValidarApiKey`, `ValidarAfirmacion`, `SincronizarNvd`, `IndexarExploitDb`, `IndexarOwaspTop10` |
| **Strategy** | `RegexAfirmacionExtractor` implementa `IAfirmacionExtractor` (intercambiable por NLP) |
| **Factory + Singleton** | `MongoConnection` (singleton), `PostgresConnection` |
| **Dependency Injection** | `DIContainer` en `infrastructure/di.py` con 13 factories lazy |
| **Pipeline (Análisis)** | `AnalizarProyecto` orquesta: embed → chroma → enrich → prompt → llm → parse → store |
| **Pipeline (Indexación)** | `IndexarExploitDb` / `IndexarOwaspTop10`: git clone → parse → MongoDB → embed → ChromaDB |

---

## Estructura del proyecto

```
src/
├── domain/              → models.py, enums.py, exceptions.py
├── ports/               → repositories.py, services.py (interfaces)
├── adapters/
│   ├── mongodb/         → connection, cve_repository, hallazgo_repository
│   ├── postgresql/      → connection, apikey_repository, conocimiento_repository
│   ├── chromadb/        → vector_store.py
│   ├── ollama/          → llm_service.py, embedding_service.py
│   ├── pdf/             → report_generator.py
│   └── afirmaciones/    → extractor.py (Strategy)
├── application/         → analizador.py, validador.py, sincronizador.py
├── infrastructure/      → config.py, di.py, logging.py
├── interfaces/
│   ├── cli/             → analizador_cli.py, generar_apikey_cli.py
│   └── api/             → validation_api.py, routers/rag.py
└── tasks/               → celery_app.py, analysis_tasks.py

tests/                   → test_apikey.py, test_validador.py, test_seguridad.py
database/                → schema.sql, init_db.py
nginx/                   → openwebui.conf (SSL + rate limiting)
patches/                 → openwebui_inject.py, inject_middleware.py
```

### Colecciones ChromaDB

| Colección | Contenido | Población |
|---|---|---|
| `nvd_vulnerabilities` | CVE con severidad, descripción y score | `python3 update_nvd_db.py` |
| `exploitdb_exploits` | Exploits con path y código | `python3 index_exploitdb.py` |
| `owasp_top10_2025` | Documentos OWASP Top 10 2025 (16 .md) | `python3 index_owasp_top10.py` |

### Colecciones MongoDB

| Colección | Propósito |
|---|---|
| `cves` | Metadatos de vulnerabilidades NVD |
| `exploits` | Texto completo de exploits |
| `owasp_top10` | Documentos OWASP Top 10 (categoría, título, risk rank) |
| `analisis` | Historial de análisis realizados |
| `hallazgos` | Vulnerabilidades encontradas por análisis |

---

## Servicios Docker

| Servicio | Puerto | Descripción |
|---|---|---|
| `ollama` | 11434 | Motor de LLMs |
| `chromadb` | 8001 | Base vectorial (NVD + ExploitDB + OWASP) |
| `mongodb` | 27017 | NoSQL (vulnerabilidades, exploits, hallazgos, OWASP) |
| `postgres` | 5432 | SQL (validación + API keys + usuarios) |
| `redis` | 6379 | Cola Celery |
| `validation-service` | 8000 | Middleware FastAPI + RAG enrichment endpoint |
| `dashboard` | 8002 | Dashboard web (estadísticas + API keys) |
| `open-webui` | 3000 | Interfaz web LLM con middleware de validación inyectado |
| `celery-worker` | - | Procesador de cola asíncrona |

---

## Correcciones de Seguridad (CodeQL)

### 5. Use of a broken or weak cryptographic hashing algorithm – Alta (NUEVA)
**Archivo:** `patches/openwebui_inject.py` línea 22

**Problema:** La función `_redact()` usaba `hashlib.sha256()` sin sal ni iteraciones para enmascarar datos sensibles en logs. CodeQL considera esto insuficiente para datos sensibles.

**Mitigación:**
- Reemplazado por `hashlib.pbkdf2_hmac('sha256', ..., salt=b'redact_salt', iterations=100000, dklen=16)`
- El hash truncado ahora usa prefijo `pbkdf2:` en lugar de `sha256:`
- La función solo se usa para **redacción en logs** (no para almacenamiento de credenciales); el almacenamiento real de API keys ya usa PBKDF2-SHA256 con 600k iteraciones en `apikey_repository.py`
- No hay migración de datos porque `_redact()` no persiste valores en BD

**Verificación:**
```bash
python3 -m pytest tests/test_seguridad.py::TestStrongHash -v
```

### 1. Clear-text logging of sensitive information
**Archivos:** `patches/openwebui_inject.py`, `src/interfaces/cli/generar_apikey_cli.py`, `test/app.js`

**Problema:** Los logs podían exponer API keys, contraseñas y consultas SQL completas.

**Mitigación:**
- Las API keys en logs se reemplazan por `sha256:<hash_truncado>` mediante la función `_redact()`
- `generar_apikey_cli.py` usa `sys.stdout.write()` en lugar de `print()` para mostrar la key una sola vez; los logs del módulo nunca incluyen la key; los mensajes de error usan `sys.stderr.write()` sin detalle de la excepción
- `test/app.js`: `console.log(query)` reemplazado por mensaje genérico sin credenciales
- Excepciones en `openwebui_inject.py` se registran sin el detalle del error para evitar fugas
- Niveles de log ajustados: operaciones internas a `DEBUG`, eventos relevantes a `INFO`, errores a `WARNING`

**Verificación:**
```bash
python3 -m pytest tests/test_seguridad.py::TestSensitiveLogging -v
```

### 2. SQL Injection
**Archivo:** `test/app.js` (líneas 43-47 y 121-125)

**Problema:** Las consultas SQL se construían con interpolación directa de strings (`... WHERE username = '${username}'`).

**Mitigación:**
- Todas las consultas convertidas a **prepared statements** con placeholders `?`
- Parámetros pasados como arreglo separado: `db.get(query, [username, password], ...)`
- Validación de tipo en `/user/:id`: se usa `parseInt(rawId, 10)` + `Number.isFinite(id)`

**Verificación:**
```bash
python3 -m pytest tests/test_seguridad.py::TestSqlInjection -v
```

### 3. Missing rate limiting
**Archivo:** `test/app.js` (líneas 40, 76, 98, 121)

**Problema:** Los endpoints `/login`, `/notes`, `/user/:id` no tenían límite de peticiones.

**Mitigación:**
- Dependencia `express-rate-limit` añadida a `package.json`
- Límite: **100 peticiones por 15 minutos** por IP en todos los endpoints
- Cabeceras `RateLimit-*` y `X-RateLimit-*` incluidas (`standardHeaders: true`, `legacyHeaders: true`)

**Verificación:**
```bash
python3 -m pytest tests/test_seguridad.py::TestRateLimiting -v
```

### 4. Exception text reinterpreted as HTML
**Archivo:** `test/app.js` (líneas 53, 128)

**Problema:** `res.send(err.message)` devolvía mensajes de error internos al cliente sin sanitizar.

**Mitigación:**
- Los errores internos devuelven `{ "error": "Error interno del servidor" }` (JSON genérico)
- Los errores reales se registran en el servidor con `console.error()`, nunca se envían al cliente
- Las respuestas HTML escapan el contenido con `escape-html()` para prevenir XSS
- Handler global de errores captura excepciones no manejadas y responde con JSON genérico

**Verificación:**
```bash
python3 -m pytest tests/test_seguridad.py::TestExceptionHandling -v
```

### Configuración de rate limiting

Los límites se configuran en `test/app.js` mediante `express-rate-limit`:

```javascript
const limiter15 = rateLimit({
  windowMs: 15 * 60 * 1000,   // ventana de 15 minutos
  max: 100,                     // máximo 100 peticiones
  standardHeaders: true,        // RateLimit-* headers
  legacyHeaders: true,          // X-RateLimit-* headers
})
```

Para producción, ajustar `windowMs` y `max` según necesidades. No requiere variables de entorno adicionales.

### Pruebas completas

```bash
# Todas las pruebas (incluyendo seguridad)
python3 -m pytest tests/ -v

# Solo pruebas de seguridad
python3 -m pytest tests/test_seguridad.py -v
```

---

## Licencia

MIT

---

Hecho para mantener tu código seguro y privado.
