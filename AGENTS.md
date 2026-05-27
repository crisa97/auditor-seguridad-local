# AGENTS.md — Contexto Completo del Proyecto

## Visión General

**Auditor de Seguridad Local con IA** — analiza proyectos de software buscando vulnerabilidades usando un pipeline RAG completamente local. Todo corre en local, ningún dato sale de la máquina.

---

## Estructura de Directorios

```
/
├── .env                          # Variables de entorno (reales)
├── .env.example                  # Template del .env
├── .gitignore
├── Modelfile                     # Definición del modelo Ollama personalizado
├── README.md
├── analizador_rag_cli.py         # Wrapper: CLI principal (delega a src/)
├── config.py                     # Wrapper: configuración (delega a src/)
├── docker-compose.yml            # 8 servicios Docker
├── Dockerfile.openwebui          # Open WebUI custom con middleware de validación
├── Dockerfile.validation         # FastAPI validation service
├── Dockerfile.worker             # Celery worker
├── generar_apikey.py             # Wrapper: generación de API keys
├── index_exploitdb.py            # Wrapper: indexación de ExploitDB
├── init-mongo.js                 # Inicialización MongoDB (colecciones + índices)
├── mongo_integration.py          # Wrapper: módulo MongoDB
├── requirements.txt              # Dependencias Python
├── setup.sh                      # Script de setup automatizado
├── tasks.py                      # Wrapper: tareas Celery
├── update_nvd_db.py              # Wrapper: sincronización NVD
├── validador.py                  # Wrapper: validación
├── validation_service.py         # Wrapper: FastAPI app
│
├── database/
│   ├── init_db.py                # Inicializador de esquema PostgreSQL
│   └── schema.sql                # DDL PostgreSQL (3 tablas)
│
├── nginx/
│   └── openwebui.conf            # Configuración Nginx (SSL, rate limiting, headers)
│
├── patches/
│   └── openwebui_inject.py       # Inyector de middleware ASGI para Open WebUI
│
├── test/                         # Proyecto de prueba Node.js
│   ├── app.js
│   └── package.json
│
├── tests/                        # Tests Python
│   ├── __init__.py
│   ├── conftest.py               # Configuración de pytest
│   ├── test_apikey.py            # Tests de API keys
│   └── test_validador.py         # Tests de validación de afirmaciones
│
└── src/
    ├── __init__.py
    │
    ├── domain/                   # Capa de dominio (Python puro, sin dependencias)
    │   ├── enums.py              # EstadoAnalisis, AccionValidacion
    │   ├── exceptions.py         # ApiKeyInvalidaError, AfirmacionBloqueadaError, etc.
    │   └── models.py             # Cve, Exploit, Hallazgo, Analisis, ApiKey, Afirmacion
    │
    ├── ports/                    # Interfaces abstractas (Puertos)
    │   ├── repositories.py       # 6 interfaces: ICveRepository, IExploitRepository, etc.
    │   └── services.py           # 5 interfaces: ILlmService, IEmbeddingService, etc.
    │
    ├── adapters/                 # Implementaciones concretas (Adaptadores)
    │   ├── mongodb/
    │   │   ├── connection.py     # MongoConnection (singleton)
    │   │   ├── cve_repository.py # MongoCveRepository, MongoExploitRepository
    │   │   └── hallazgo_repository.py  # MongoHallazgoRepository, MongoAnalisisRepository
    │   ├── postgresql/
    │   │   ├── connection.py     # PostgresConnection (factory method)
    │   │   ├── apikey_repository.py    # PostgresApiKeyRepository + hash_api_key()
    │   │   └── conocimiento_repository.py  # PostgresConocimientoRepository
    │   ├── chromadb/
    │   │   └── vector_store.py   # ChromaVectorStore
    │   ├── ollama/
    │   │   ├── llm_service.py    # OllamaLlmService
    │   │   └── embedding_service.py  # OllamaEmbeddingService
    │   ├── pdf/
    │   │   └── report_generator.py  # PdfReportGenerator (txt + PDF)
    │   └── afirmaciones/
    │       └── extractor.py      # RegexAfirmacionExtractor (Strategy pattern)
    │
    ├── application/              # Casos de uso
    │   ├── analizador.py        # AnalizarProyecto (pipeline principal)
    │   ├── validador.py         # ValidarApiKey + ValidarAfirmacion
    │   └── sincronizador.py     # SincronizarNvd + IndexarExploitDb
    │
    ├── infrastructure/           # Aspectos transversales
    │   ├── config.py            # Settings dataclass (carga de .env)
    │   ├── di.py                # DIContainer (contenedor DI con fábricas lazy)
    │   └── logging.py           # setup_logging
    │
    ├── interfaces/              # Puntos de entrada
    │   ├── cli/
    │   │   ├── analizador_cli.py       # CLI principal (argparse)
    │   │   └── generar_apikey_cli.py   # CLI de generación de API keys
    │   └── api/
    │       ├── validation_api.py       # FastAPI app
    │       └── routers/
    │           └── rag.py              # POST /api/v1/rag/consultar
    │
    └── tasks/                   # Tareas Celery
        ├── celery_app.py        # Configuración de Celery
        └── analysis_tasks.py    # analizar_proyecto (tarea asíncrona)
```

---

## Stack Tecnológico

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3.11+ |
| Web Framework | FastAPI |
| LLM Engine | Ollama (deepseek-coder-v2:16b → "auditor-seguridad") |
| Embeddings | nomic-embed-text (Ollama) |
| Vector DB | ChromaDB |
| NoSQL DB | MongoDB 7 (vulnerabilidades, exploits, hallazgos, análisis) |
| SQL DB | PostgreSQL 16 (API keys, conocimiento validado) |
| Message Broker | Redis 7 (Celery) |
| Task Queue | Celery |
| PDF Generation | ReportLab |
| Proxy | Nginx (SSL, rate limiting, seguridad) |
| Web UI | Open WebUI |
| Testing | Pytest + mocking |
| DI | DIContainer custom (singleton + factory) |
| API Auth | PBKDF2-SHA256 (600k iteraciones) |
| Contenedores | Docker + Docker Compose |

---

## Arquitectura: Hexagonal (Ports & Adapters)

```
INTERFACES (CLI / FastAPI API)
    │  llama
    ▼
APPLICATION (casos de uso)
    │  usa
    ▼
    PORTS (interfaces abstractas)
    │  implementa
    ▼
ADAPTERS (MongoDB, PostgreSQL, ChromaDB, Ollama, PDF)
    │
INFRASTRUCTURE (config, DI, logging)
```

### Flujo del Pipeline de Análisis (AnalizarProyecto)

1. Recorre directorio del proyecto (filtra por extensiones, ignora directorios comunes)
2. Por cada archivo:
   a. Genera embedding del texto
   b. Consulta ChromaDB por CVEs y Exploits similares (RAG)
   c. Construye prompt enriquecido con contexto de vulnerabilidades reales
   d. Llama al LLM (Ollama) con el prompt
   e. Parsea la respuesta estructurada en hallazgos
   f. Almacena en MongoDB
3. Genera reportes TXT + PDF
4. Opcional: envía resultados al servicio de validación

---

## Convenciones de Código

- **Python 3.11+** con type hints en todas las funciones
- **Arquitectura Hexagonal**: dominio → puertos → adaptadores → aplicación → interfaces
- **Nombrado**: `snake_case` para variables/funciones, `PascalCase` para clases, `SCREAMING_SNAKE_CASE` para constantes
- **Interfaces**: Prefijo `I` (ej: `ILlmService`, `ICveRepository`)
- **Excepciones**: Sufijo `Error` o `Exception`, heredan de `DomainError`
- **DI**: Contenedor propio (`DIContainer`) con fábricas lazy, acceso tipo `container.analizador()`
- **Tests**: Pytest en `tests/`, usar `conftest.py` para fixtures, mocks para adaptadores
- **Logging**: Usar `logger = logging.getLogger(__name__)` a nivel módulo
- **Config**: Toda la configuración en `src/infrastructure/config.py` (dataclass `Settings`)
- **Root wrappers**: Los archivos `.py` raíz son wrappers delgados que delegan a `src/`

---

## Configuración (.env)

Variables organizadas en 10 secciones: Ollama, ChromaDB, NVD, Embeddings, Análisis, MongoDB, ExploitDB, NVD batch, Celery, Validación/API Keys.

Ver `.env.example` para lista completa.

---

## Servicios Docker (8 en total)

| Servicio | Puerto | Propósito |
|---|---|---|
| ollama | 11434 | Runtime LLM |
| ollama-init | — | Pull modelos + crear `auditor-seguridad` (one-shot) |
| chromadb | 8001 | Vector store |
| mongodb | 27017 | Base de datos NoSQL |
| postgres | 5432 | Base de datos SQL |
| redis | 6379 | Broker de Celery |
| celery-worker | — | Procesa tareas asíncronas |
| validation-service | 8000 | API FastAPI (2 réplicas) |
| open-webui | 3000 | Interfaz web LLM |

---

## Endpoints API

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/rag/consultar` | Consulta RAG con validación de API key + afirmaciones |

---

## Modelos de Datos

### MongoDB — `vulnerabilidades`
- `cves`: `{ id, description, severity, score, chromaId }`
- `exploits`: `{ id, path, text, chromaId }`
- `analisis`: `{ projectPath, timestamp, estado, totalFiles, archivosAnalizados, taskId, reporteTxt, reportePdf, error }`
- `hallazgos`: `{ analisisId, filepath, severidad, titulo, descripcion, mitigacion, ubicacion, cve_cwe, raw_response }`

### PostgreSQL — `openwebui`
- `conocimiento_validado`: `{ id, texto_afirmacion (hash index), es_verdadero, fuente, fecha_validacion }`
- `pendiente_validacion`: `{ id, texto_afirmacion, consulta_original, modelo_respuesta, revisado }`
- `api_keys`: `{ id, key_hash (unique, hash index), key_prefix, nombre_cliente, fecha_expiracion, activa, permisos }`

---

## Patrones de Diseño

| Patrón | Implementación |
|---|---|
| Hexagonal Architecture | 4 capas: domain, ports, adapters, application/interfaces |
| Repository | 6 interfaces con impls MongoDB/PostgreSQL |
| Service Layer | Casos de uso: AnalizarProyecto, ValidarApiKey, etc. |
| Strategy | RegexAfirmacionExtractor implementa IAfirmacionExtractor |
| Singleton | MongoConnection |
| Factory | PostgresConnection.get_conn() |
| Dependency Injection | DIContainer (13 fábricas lazy) |
| Pipeline | AnalizarProyecto orquesta: embed → chroma → prompt → llm → parse → store → report |
| Facade/Proxy | Root `.py` wrappers que delegan a `src/` |
| Middleware | openwebui_inject.py inyecta middleware ASGI en Open WebUI |

---

## Dependencias Principales

```
nvdlib, chromadb, reportlab, requests, ollama, pymongo,
celery, redis, python-dotenv, fastapi, uvicorn,
psycopg2-binary, pydantic, pytest, bcrypt
```

---

## Testing

```bash
python3 -m pytest tests/ -v
```

- `tests/test_apikey.py` — generación y validación de API keys
- `tests/test_validador.py` — extracción y validación de afirmaciones
- Usar `conftest.py` para fixtures compartidos
- Mockear adaptadores (Ollama, MongoDB, PostgreSQL, ChromaDB) en tests unitarios
