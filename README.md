# Auditor de Seguridad Local con IA

Analiza **cualquier proyecto de código fuente** en busca de vulnerabilidades de forma **100% local y privada**, combinando un LLM especializado en seguridad con RAG sobre datos reales del NVD, ExploitDB y OWASP Top 10 2025.

Dos modos de uso:
- **CLI local** — ejecuta el pipeline completo en tu máquina (requiere Docker + Ollama)
- **CLI remoto** — envía archivos a un servidor central, sin dependencias locales

---

## Arquitectura (Hexagonal / Ports & Adapters)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              INTERFACES                                           │
│  ┌──────────────────┐  ┌──────────────┐  ┌────────────────┐  ┌────────────────┐  │
│  │  analizador_cli   │  │ cli_remoto   │  │ validation_api │  │ dashboard      │  │
│  │  (local + queue)  │  │ (standalone) │  │ (FastAPI v1+v2)│  │ (FastAPI JWT)  │  │
│  └────────┬─────────┘  └──────┬───────┘  └───────┬────────┘  └───────┬────────┘  │
└───────────┼───────────────────┼──────────────────┼──────────────────┼────────────┘
            │                   │                  │                  │
┌───────────┼───────────────────┼──────────────────┼──────────────────┼────────────┐
│           ▼                   ▼                  ▼                  ▼            │
│                        APPLICATION (casos de uso)                                │
│  ┌──────────────────┐  ┌────────────────┐  ┌────────────────────────────────┐   │
│  │ AnalizarProyecto  │  │ ValidarApiKey  │  │ SincronizarNvd                 │   │
│  │ (paralelo + lote) │  │ ValidarAfirm.  │  │ IndexarExploitDb              │   │
│  │                   │  │                │  │ IndexarOwaspTop10             │   │
│  └────────┬─────────┘  └───────┬────────┘  │ Enrichir (RAG)                 │   │
└───────────┼────────────────────┼───────────┴────────────────────────────────┘   │
            │                    │                                                   │
┌───────────┼────────────────────┼───────────────────────────────────────────────────┘
│           ▼                    ▼                                                    │
│                    PORTS (interfaces abstractas)                                    │
│  ┌──────────────┐  ┌─────────────────┐  ┌───────────────┐  ┌──────────────────┐    │
│  │ IHallazgoRepo │  │ IApiKeyRepo     │  │ ILlmService   │  │ IReportGenerator │    │
│  │ IAnalisisRepo │  │ IConocimientoRep│  │ IEmbedding    │  │ (PDF + TXT +     │    │
│  │ ICveRepo      │  │                 │  │ IVectorStore  │  │  generate_bytes) │    │
│  └───────┬───────┘  └────────┬────────┘  └───────┬───────┘  └────────┬─────────┘    │
└──────────┼────────────────────┼──────────────────┼───────────────────┼──────────────┘
           │                    │                  │                   │
┌──────────┼────────────────────┼──────────────────┼───────────────────┼──────────────┐
│          ▼                    ▼                  ▼                   ▼             │
│                      ADAPTERS (implementaciones)                                   │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │ MongoHallazgo│  │ PostgresApiKey   │  │ OllamaLlm    │  │ PdfReportGenerator│   │
│  │ MongoAnalisis│  │ PostgresConocim. │  │ OllamaEmbed. │  │ (txt + pdf +      │   │
│  │ (GridFS PDF) │  │                  │  │ ChromaVector │  │  pdf_bytes)       │   │
│  └──────────────┘  └──────────────────┘  └──────────────┘  └──────────────────┘    │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## Requisitos

### Modo local (CLI + pipeline completo)
- **Docker** y **Docker Compose**
- **Python 3.10+**
- **RAM**: 8 GB mínimos / 16 GB recomendados

### Modo remoto (solo CLI)
- **Python 3.10+** con `requests`
- Sin Docker, sin Ollama, sin bases de datos

---

## Instalación rápida

### 1. Infraestructura (servidor)

```bash
git clone <repo> && cd seguridad-local
cp .env.example .env
nano .env   # ajustar contraseñas, hosts, etc.
docker compose up -d
pip install -r requirements.txt
```

### 2. Sincronizar bases de datos

```bash
python3 update_nvd_db.py          # NVD (CVE últimos 90 días)
python3 index_exploitdb.py        # ExploitDB
python3 index_owasp_top10.py      # OWASP Top 10 2025
```

### 3. Migración (para instalaciones existentes)

```bash
psql -U openwebui -d openwebui -f database/migracion_v2_usuario_id.sql
python3 migracion_backfill_usuario_id.py
```

---

## Uso del CLI local

El CLI local requiere acceso a la infraestructura Docker (Ollama, ChromaDB, MongoDB):

```bash
# Escanear un proyecto completo
python3 analizador_rag_cli.py /ruta/al/proyecto

# Con API key
python3 analizador_rag_cli.py --api-key "sk-xxx" /ruta/al/proyecto

# Encolar en Celery (asíncrono)
python3 analizador_rag_cli.py --queue /ruta/al/proyecto

# Consultar estado de análisis encolado
python3 analizador_rag_cli.py --status <task_id>

# Listar análisis realizados
python3 analizador_rag_cli.py --list
```

### Resultados

El análisis genera dos archivos en `reportes/`:
- `informe_seguridad_<fecha>.txt`
- `informe_seguridad_<fecha>.pdf`

---

## Uso del CLI remoto

El CLI remoto es **standalone** — solo necesita `requests`. Envía los archivos al servidor, que ejecuta el pipeline completo:

```bash
python3 cli_remoto.py \
  --server https://midominio.com \
  --api-key sk_abc123... \
  /ruta/al/proyecto
```

El servidor:
1. Valida la API key (permiso `rag:analizar`)
2. Genera embedding único del proyecto
3. Consulta ChromaDB (NVD + ExploitDB)
4. Ejecuta el LLM en paralelo (3 workers)
5. Almacena hallazgos en MongoDB asociados al usuario
6. Guarda el PDF del reporte en GridFS
7. Devuelve resumen + URL del PDF

El reporte PDF queda accesible desde el dashboard web o directamente:
- Visualizar: `GET /api/v2/rag/reportes/{analisis_id}`
- Descargar: `GET /api/v2/rag/reportes/{analisis_id}?download=true`

---

## Dashboard Web

Accesible en `http://localhost:8001/dashboard/` con autenticación JWT.

### Roles

| Rol | Acceso |
|---|---|
| `admin` | Estadísticas globales, todos los análisis, todos los hallazgos, CVEs indexados |
| `usuario` | Solo sus propios análisis y hallazgos (filtrados por `usuario_id`) |

### Endpoints

| Método | Ruta | Roles | Descripción |
|---|---|---|---|
| `POST` | `/api/v2/auth/login` | — | Login (JWT) |
| `POST` | `/api/v2/auth/register` | admin | Registrar usuario |
| `POST` | `/api/v2/auth/refresh` | — | Refrescar JWT |
| `GET` | `/api/v2/dashboard/stats` | admin | Estadísticas globales |
| `GET` | `/api/v2/dashboard/analisis` | admin, usuario | Lista de análisis (filtrados por usuario) |
| `GET` | `/api/v2/dashboard/hallazgos` | admin, usuario | Fallos de seguridad (filtrados) |
| `GET` | `/api/v2/dashboard/vulnerabilidades` | admin | CVEs indexados |
| `POST` | `/api/v2/dashboard/apikeys` | usuario, admin | Crear API key |

---

## API de análisis remoto (v2)

### `POST /api/v2/rag/analizar`

Analiza un proyecto enviando todos los archivos en un solo request:

```bash
curl -X POST https://midominio.com/api/v2/rag/analizar \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "sk_abc123...",
    "nombre_proyecto": "mi-app",
    "archivos": [
      {"filepath": "src/app.js", "contenido": "const express = ..."},
      {"filepath": "src/config.js", "contenido": "module.exports = ..."}
    ]
  }'
```

Respuesta:

```json
{
  "analisis_id": "664abc...",
  "status": "completado",
  "total_archivos": 42,
  "total_hallazgos": 5,
  "hallazgos": [
    {"filepath": "src/app.js", "severidad": "Alta", "titulo": "SQL Injection", "ubicacion": "línea 23"}
  ],
  "pdf_url": "/api/v2/rag/reportes/664abc..."
}
```

### `GET /api/v2/rag/reportes/{analisis_id}`

- Sin parámetros: visualiza el PDF en el navegador (`Content-Disposition: inline`)
- `?download=true`: fuerza la descarga (`Content-Disposition: attachment`)

---

## Generación de API Keys

```bash
# Desde el CLI (local)
python3 generar_apikey.py --cliente "Cliente ACME" --permisos "rag:leer" --dias 365

# Desde el dashboard (web)
POST /api/v2/dashboard/apikeys
  {"nombre_cliente": "Mi App", "permisos": "rag:analizar", "dias_validez": 365}
```

### Permisos disponibles

| Permiso | Descripción |
|---|---|
| `rag:leer` | Consultar RAG (endpoint `/consultar`) |
| `rag:analizar` | Ejecutar análisis remoto (endpoint `/analizar`) |
| `rag:*` | Acceso total a todos los endpoints RAG |

Las API keys se almacenan como hash PBKDF2-SHA256 con 600k iteraciones, asociadas al usuario que las creó (`usuario_id`).

---

## Optimizaciones de rendimiento

El pipeline de análisis (`AnalizarProyecto`) incluye 7 optimizaciones para proyectos grandes:

### 1. Paralelización con ThreadPoolExecutor
- 3 workers simultáneos (configurable vía `ANALYSIS_MAX_WORKERS`)
- Las llamadas al LLM (I/O-bound) corren en paralelo
- Ganancia: ~3x más rápido que secuencial

### 2. Semáforo de Ollama
- `threading.Semaphore(max_workers)` evita saturar Ollama
- Cada hilo espera su turno antes de llamar al LLM

### 3. Embedding único por proyecto
- Se genera **un solo embedding** del resumen del proyecto
- **Una sola consulta** a ChromaDB (NVD + ExploitDB), reusada para todos los archivos
- Caché por hash MD5 para evitar re-embedding
- Controlado por `ANALYSIS_USE_PROJECT_EMBEDDING=true`
- Ganancia: elimina N embeddings + 2N ChromaDB queries

### 4. Combinación de archivos pequeños
- Archivos < 50 líneas se agrupan en un solo prompt
- Un lote contiene `# --- filepath ---\ncontenido` por archivo
- Controlado por `ANALYSIS_COMBINE_SMALL_FILES=true` y `ANALYSIS_SMALL_FILE_LINES=50`
- Ganancia: archivos pequeños se procesan ~5x más rápido

### 5. Filtro de archivos minificados
- Omite automáticamente `.min.js`, `.min.css`, `.bundle.js`, `.chunk.js`
- Omite archivos > 512 KB (`ANALYSIS_MAX_FILE_SIZE_KB=512`)

### 6. Caché de CVEs
- `@lru_cache(maxsize=256)` — los mismos CVEs no re-consultan MongoDB

### 7. GridFS para PDFs
- Los reportes PDF se almacenan en MongoDB GridFS
- Accesibles vía API REST (visualización inline o descarga)

### Proyección de tiempos (juice-shop, 996 archivos)

| Modo | Tiempo estimado |
|---|---|
| Sin optimizar (secuencial) | ~5 horas |
| Con optimizaciones (3 workers) | ~1 hora |
| ~5x más rápido | |

---

## Middleware de validación (anti-falsos positivos)

Servicio FastAPI que intercepta consultas a Open WebUI:

1. **API key** contra PostgreSQL (tabla `api_keys`)
2. **Afirmaciones** contra conocimiento validado (tabla `conocimiento_validado`)
3. **Enriquecimiento RAG automático** — consulta ChromaDB (NVD + ExploitDB + OWASP) e inyecta contexto como mensaje `system`

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Consultar con validación
curl -X POST http://localhost:8000/api/v1/rag/consultar \
  -H "Content-Type: application/json" \
  -d '{"texto": "consulta", "api_key": "sk-xxx"}'

# Enriquecimiento RAG
curl -X POST http://localhost:8000/api/v1/rag/enrichir \
  -H "Content-Type: application/json" \
  -d '{"texto": "SQL injection", "api_key": "token-interno"}'
```

---

## Módulo OWASP Top 10 2025

Indexa los 16 documentos del OWASP Top 10 2025 en MongoDB + ChromaDB:

```bash
python3 index_owasp_top10.py
```

| ID | Documento | Categoría |
|---|---|---|
| `0x00` – `0x03` | Introducción, About OWASP, Risk Methodology | Contexto |
| `A01` – `A10` | Broken Access Control, Injection, Cryptographic Failures... | Riesgos |
| `X01` | Next Steps (Vibe Coding, Memory Mgmt...) | Bonus |

---

## Sincronización de bases de datos

```bash
python3 update_nvd_db.py           # NVD (últimos 90 días)
python3 index_exploitdb.py         # ExploitDB (filtra binarios automáticamente)
python3 index_owasp_top10.py       # OWASP Top 10 2025
python3 analizador_rag_cli.py --update-nvd  # Forzar actualización desde el CLI
```

---

## Estructura del proyecto

```
/
├── cli_remoto.py                   # CLI remoto (standalone, solo requests)
├── analizador_rag_cli.py           # CLI local (argparse)
├── generar_apikey.py               # Generación de API keys
├── migracion_backfill_usuario_id.py # Backfill MongoDB + PostgreSQL
├── update_nvd_db.py                # Sincronización NVD
├── index_exploitdb.py              # Indexación ExploitDB
├── index_owasp_top10.py            # Indexación OWASP Top 10
├── validation_service.py           # FastAPI (v1 + v2)
├── validador.py                    # Validación wrapper
│
├── src/
│   ├── domain/                     # models, enums, exceptions
│   ├── ports/                      # interfaces abstractas
│   ├── adapters/
│   │   ├── mongodb/                # repos + GridFS
│   │   ├── postgresql/             # repos + hash API keys
│   │   ├── chromadb/               # vector store
│   │   ├── ollama/                 # LLM + embeddings
│   │   ├── pdf/                    # generación de reportes
│   │   └── afirmaciones/           # extractor de afirmaciones
│   ├── application/                # casos de uso
│   ├── infrastructure/             # config, DI, logging
│   ├── interfaces/
│   │   ├── cli/                    # analizador_cli, generar_apikey_cli
│   │   ├── api/                    # FastAPI + routers
│   │   └── dashboard/              # dashboard web con JWT
│   └── tasks/                      # Celery workers
│
├── database/                       # schema.sql, migraciones
├── nginx/                          # openwebui.conf (SSL + rate limiting)
├── patches/                        # middleware Open WebUI
└── tests/                          # pytest (API keys, validación, seguridad)
```

### Colecciones ChromaDB

| Colección | Contenido | Población |
|---|---|---|
| `nvd_vulnerabilities` | CVE con severidad y score | `update_nvd_db.py` |
| `exploitdb_exploits` | Exploits con path y código | `index_exploitdb.py` |
| `owasp_top10_2025` | Documentos OWASP Top 10 | `index_owasp_top10.py` |

### Colecciones MongoDB

| Colección | Propósito |
|---|---|
| `cves` | Metadatos de vulnerabilidades NVD |
| `exploits` | Texto completo de exploits |
| `owasp_top10` | Documentos OWASP Top 10 |
| `analisis` | Análisis realizados (con `usuarioId`) |
| `hallazgos` | Vulnerabilidades encontradas (con `usuarioId`) |
| `fs.files` / `fs.chunks` | PDFs de reportes (GridFS) |

### Tablas PostgreSQL

| Tabla | Propósito |
|---|---|
| `api_keys` | API keys (hash PBKDF2 + `usuario_id`) |
| `conocimiento_validado` | Afirmaciones verificadas (anti-falsos positivos) |
| `pendiente_validacion` | Afirmaciones pendientes de revisión |
| `users` | Usuarios del dashboard (admin/usuario) |

---

## Servicios Docker

| Servicio | Puerto | Descripción |
|---|---|---|
| `ollama` | 11434 | Motor de LLMs (qwen2.5-coder:7b) |
| `chromadb` | 8001 | Base vectorial |
| `mongodb` | 27017 | NoSQL (vulns, exploits, hallazgos, PDFs) |
| `postgres` | 5432 | SQL (API keys, usuarios, validación) |
| `redis` | 6379 | Cola Celery |
| `validation-service` | 8000 | FastAPI (v1 + v2 + RAG) |
| `dashboard` | 8001 | Dashboard web JWT |
| `open-webui` | 3000 | Interfaz web LLM |
| `celery-worker` | — | Procesador asíncrono |

---

## Variables de entorno

### Análisis y optimización

| Variable | Default | Descripción |
|---|---|---|
| `ANALYSIS_MAX_WORKERS` | `3` | Hilos paralelos para analizar archivos |
| `ANALYSIS_USE_PROJECT_EMBEDDING` | `true` | Embedding único del proyecto |
| `ANALYSIS_COMBINE_SMALL_FILES` | `true` | Agrupar archivos < 50 líneas |
| `ANALYSIS_SMALL_FILE_LINES` | `50` | Máx líneas para archivo "pequeño" |
| `ANALYSIS_MAX_FILE_SIZE_KB` | `512` | Archivos > 512 KB se omiten |
| `ANALYSIS_CHUNK_SIZE` | `8000` | Caracteres máximos por prompt |
| `ANALYSIS_MAX_CONTEXT_CHARS` | `2000` | Caracteres máximos del contexto RAG |

### Enriquecimiento RAG

| Variable | Default | Descripción |
|---|---|---|
| `RAG_AUTO_ENRICH` | `true` | Enriquecimiento automático desde Open WebUI |
| `RAG_MAX_CVES` | `5` | Máximo de CVEs por consulta |
| `RAG_MAX_EXPLOITS` | `5` | Máximo de exploits por consulta |
| `RAG_MAX_OWASP` | `3` | Máximo de documentos OWASP por consulta |

---

## Pruebas

```bash
python3 -m pytest tests/ -v
```

---

## Patrones de diseño

| Patrón | Implementación |
|---|---|
| **Arquitectura Hexagonal** | Domain → Ports → Adapters → Application → Interfaces |
| **Repository** | 7 interfaces con impls MongoDB/PostgreSQL |
| **Service Layer** | AnalizarProyecto, ValidarApiKey, SincronizarNvd, etc. |
| **Strategy** | RegexAfirmacionExtractor implementa IAfirmacionExtractor |
| **Factory + Singleton** | MongoConnection (singleton), PostgresConnection |
| **Dependency Injection** | DIContainer con 13 factories lazy |
| **Pipeline (Análisis)** | embed → chroma → prompt → llm → parse → store |
| **Pipeline (Indexación)** | git clone → parse → MongoDB → embed → ChromaDB |

---

## Licencia

MIT

---

Hecho para mantener tu código seguro y privado. Sin datos que salgan de tu máquina.
