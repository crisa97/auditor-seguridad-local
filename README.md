# Auditor de Seguridad Local con IA

Analiza **cualquier proyecto de código fuente** en busca de vulnerabilidades de forma **100% local y privada**, combinando un LLM especializado en seguridad con RAG sobre datos reales del NVD y ExploitDB.

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
│  └────────┬─────────┘  └────────┬─────────┘  │ IndexarExploitDb │  │
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
│  │ MongoHallazgo   │  │ PostgresConocim.  │  │ OllamaEmbedding   │    │
│  │ MongoAnalisis   │  │                   │  │ ChromaVectorStore │    │
│  └────────────────┘  └───────────────────┘  │ PdfReportGenerator│    │
│                                              └──────────────────┘     │
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

## Middleware de validación (anti-falsos positivos)

Servicio FastAPI que intercepta consultas a Open WebUI y valúa:

1. **API key** contra PostgreSQL (`api_keys`)
2. **Afirmaciones** contra conocimiento validado (`conocimiento_validado`)
3. Si hay falsos positivos conocidos → bloquea la respuesta

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Consultar con validación
curl -X POST http://localhost:8000/api/v1/rag/consultar \
  -H "Content-Type: application/json" \
  -d '{"texto": "consulta", "api_key": "sk-xxx"}'
```

Documentación interactiva: http://localhost:8000/api/v1/docs

---

## Sincronización de bases de datos

```bash
# NVD (CVE de los últimos 90 días)
python3 update_nvd_db.py

# ExploitDB
python3 index_exploitdb.py

# Forzar actualización NVD desde el CLI
python3 analizador_rag_cli.py --update-nvd /ruta/proyecto
```

---

## Pruebas

```bash
python3 -m pytest tests/ -v
```

---

## Patrones de diseño aplicados

| Patrón | Implementación |
|---|---|
| **Arquitectura Hexagonal** | Capas domain → ports → adapters → application → interfaces |
| **Repository** | 6 interfaces (`ICveRepository`, `IApiKeyRepository`, etc.) con implementaciones MongoDB/PostgreSQL |
| **Service Layer** | Casos de uso: `AnalizarProyecto`, `ValidarApiKey`, `ValidarAfirmacion`, `SincronizarNvd` |
| **Strategy** | `RegexAfirmacionExtractor` implementa `IAfirmacionExtractor` (intercambiable por NLP) |
| **Factory + Singleton** | `MongoConnection` (singleton), `PostgresConnection` |
| **Dependency Injection** | `DIContainer` en `infrastructure/di.py` con 10 factories lazy |
| **Pipeline** | `AnalizarProyecto` orquesta: embed → chroma → enrich → prompt → llm → parse → store |

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

tests/                   → test_apikey.py, test_validador.py
database/                → schema.sql
nginx/                   → openwebui.conf (SSL + rate limiting)
```

---

## Servicios Docker

| Servicio | Puerto | Descripción |
|---|---|---|
| `ollama` | 11434 | Motor de LLMs |
| `chromadb` | 8001 | Base vectorial |
| `mongodb` | 27017 | NoSQL (vulnerabilidades) |
| `postgres` | 5432 | SQL (validación + API keys) |
| `redis` | 6379 | Cola Celery |
| `validation-service` | 8000 | Middleware FastAPI |
| `open-webui` | 3000 | Interfaz web |
| `celery-worker` | - | Procesador de cola |

---

## Correcciones de Seguridad (CodeQL)

### 1. Clear-text logging of sensitive information
**Archivos:** `patches/openwebui_inject.py`, `src/interfaces/cli/generar_apikey_cli.py`, `test/app.js`

**Problema:** Los logs podían exponer API keys, contraseñas y consultas SQL completas.

**Mitigación:**
- Las API keys en logs se reemplazan por `sha256:<hash_truncado>` mediante la función `_redact()`
- `generar_apikey_cli.py` usa `sys.stdout.write()` en lugar de `print()` para mostrar la key una sola vez; los logs del módulo nunca incluyen la key
- `test/app.js`: `console.log(query)` reemplazado por mensaje genérico sin credenciales
- Excepciones en `openwebui_inject.py` se registran sin el detalle del error para evitar fugas

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
- Validación de tipo en `/user/:id`: solo se aceptan IDs numéricos (`/^\d+$/`)

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
- Cabeceras `RateLimit-*` estándar incluidas (`standardHeaders: true`)

**Verificación:**
```bash
python3 -m pytest tests/test_seguridad.py::TestRateLimiting -v
```

### 4. Exception text reinterpreted as HTML
**Archivo:** `test/app.js` (líneas 53, 128)

**Problema:** `res.send(err.message)` devolvía mensajes de error internos al cliente sin sanitizar.

**Mitigación:**
- Los errores internos devuelven `{ "error": "Error interno del servidor" }` (JSON genérico)
- Los errores reales se registran en el servidor con `console.error()`
- Las respuestas HTML escapan el contenido con `escape-html` para prevenir XSS

**Verificación:**
```bash
python3 -m pytest tests/test_seguridad.py::TestExceptionHandling -v
```

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
