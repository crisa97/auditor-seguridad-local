# 🛡️ Auditor de Seguridad Local con IA (Ollama + ChromaDB + NVD)

Analiza **cualquier proyecto de código fuente** en busca de vulnerabilidades de forma **100% local y privada**, combinando un modelo de lenguaje especializado en seguridad con una base de conocimiento enriquecida con datos reales del [National Vulnerability Database (NVD)](https://nvd.nist.gov/).

Todo corre dentro de contenedores Docker, sin enviar tu código a ningún servicio externo.

---

## ✨ Características

- 🔒 **Privacidad total** – análisis completamente offline, los datos nunca abandonan tu máquina.
- 🧠 **Modelo experto en seguridad** – creado a partir de un modelo base (DeepSeek‑Coder o CodeLlama) y afinado con un *system prompt* orientado a ciberseguridad ofensiva/defensiva.
- 📚 **Base de conocimiento actualizable** – se conecta al NVD (via API) y guarda las vulnerabilidades en ChromaDB para enriquecer cada análisis mediante **RAG (Retrieval‑Augmented Generation)**.
- 📄 **Informes profesionales** – genera reportes en formato **TXT** y **PDF** con los hallazgos clasificados por severidad y archivo.
- 🌐 **Interfaz web opcional** – incluye [Open WebUI](https://github.com/open-webui/open-webui) para interactuar manualmente con el modelo a través de un chat local.
- ⚙️ **Actualización automática** – la base NVD se refresca cada semana (o bajo demanda) sin intervención manual.
- 🐳 **Totalmente contenerizado** – Docker Compose levanta todos los servicios necesarios (Ollama, ChromaDB, Open WebUI) con un solo comando.

---

## 🏗️ Arquitectura
```text
┌──────────────────────────────────────────────────────┐
│                Tu PC / VM Linux                     │
│          (Parrot OS, Ubuntu, Kali, etc.)            │
│                                                      │
│                   Docker Compose                     │
│                                                      │
│   ┌─────────────┐   ┌──────────────┐ ┌────────────┐  │
│   │   Ollama    │   │   ChromaDB   │ │ OpenWebUI │  │
│   │  (LLMs IA)  │   │ (Vector DB)  │ │ Dashboard  │  │
│   └──────┬──────┘   └──────┬───────┘ └────────────┘  │
│          │                 │                         │
│          └─────────────────┴───────────────┐         │
│                                            │         │
│      ┌────────────────────────────────┐    │         │
│      │      Scripts Python Host       │    │         │
│      │                                │    │         │
│      │ • update_nvd_db.py             │    │         │
│      │   Sincroniza CVEs desde NVD    │    │         │
│      │                                │    │         │
│      │ • analizador_rag_cli.py        │    │         │
│      │   Analiza proyectos con IA     │    │         │
│      └────────────────────────────────┘    │         │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## 📋 Requisitos

### Hardware recomendado

| Modelo                  | RAM mínima libre | Disco       |
|------------------------|------------------|-------------|
| `codellama:7b`         | 8 GB             | ~5 GB       |
| `deepseek-coder-v2:16b` | 16 GB \*         | ~10 GB      |

\* *deepseek-coder-v2:16b* necesita **~12.4 GB** de RAM para cargarse. Asegúrate de que tu máquina tenga al menos 16 GB totales y que puedas asignar suficientes recursos a Docker.  
Si tu equipo es más limitado, usa `codellama:7b` (ver [configuración para RAM baja](#-configuración-para-máquinas-con-poca-ram)).

### Software

- [Docker](https://docs.docker.com/engine/install/) y [Docker Compose](https://docs.docker.com/compose/install/) instalados.
- Python 3.10+ (en el host).
- Conexión a internet **solo para la descarga inicial de modelos y la sincronización del NVD**. Luego puedes trabajar completamente offline.

---

## 🚀 Instalación y puesta en marcha

### 1. Clona el repositorio

```bash
git clone https://github.com/crisa97/auditor-seguridad-local.git
cd auditor-seguridad-local 
```
### 2. Levanta los servicios Docker

```bash
docker compose up -d
```

La primera vez descargará las imágenes (~2 GB) y los modelos de Ollama (~9 GB para DeepSeek), lo que puede tardar varios minutos. Usa docker logs -f ollama-init para seguir el progreso.

Cuando aparezca "Modelos listos" en los logs, todos los servicios estarán operativos.

### 3. Instala las dependencias de Python

```bash
pip install -r requirements.txt
```
### 4. Sincroniza la base de datos NVD

```bash
python3 update_nvd_db.py
```
Esto descarga las vulnerabilidades (CVE) de los últimos 90 días y las almacena en ChromaDB. La primera sincronización puede tardar bastante (procesa ~15 000 – 20 000 documentos en lotes). Si se interrumpe, puedes volver a ejecutarlo y retomará donde se quedó.

### 5. ¡A analizar!

```bash
python3 analizador_rag_cli.py /ruta/a/tu/proyecto
```
Al finalizar obtendrás dos archivos en la carpeta actual:

- informe_seguridad.txt
- informe_seguridad.pdf

---

# ⚙️ Configuración para máquinas con poca RAM

Si no dispones de suficiente memoria para el modelo **deepseek-coder-v2:16b**, sigue estos pasos para usar el modelo ligero **codellama:7b**:

1. Detén los servicios:

```bash
docker compose down
```

2. Edita el archivo **Modelfile** y cambia la línea **FROM deepseek-coder-v2:16b** por:

```bash
FROM codellama:7b
```

3. En **docker-compose.yml**, modifica el comando del servicio **ollama-init** para que descargue el modelo correcto. Busca la línea:

```bash
ollama pull deepseek-coder-v2:16b
```
y sustitúyela por:

```bash
ollama pull codellama:7b
```
4. Vuelve a levantar los contenedores:

```bash
docker compose up -d
```

5. Una vez finalizada la nueva descarga (menos de 5 GB), podrás ejecutar el análisis sin problemas de memoria.

El resto del funcionamiento (scripts, base NVD, Open WebUI) permanece idéntico.

---

# 📡 Uso de la interfaz web (Open WebUI)

Accede a http://localhost:3000, crea una cuenta local y selecciona el modelo auditor-seguridad.
Desde allí puedes pegar fragmentos de código o subir archivos para análisis interactivo, usando la misma base de conocimiento vectorial.

---

# 🗓️ Actualización automática de la base NVD

El script **analizador_rag_cli.py** comprueba cada vez que se ejecuta si han pasado 7 días desde la última sincronización. Si es el caso, actualiza automáticamente las CVEs antes de analizar.

También puedes forzar la actualización manual con:

```bash
python3 update_nvd_db.py
```
Para una actualización periódica desatendida, añade una entrada al cron (ejemplo: cada lunes a las 3 AM):

```bash
0 3 * * 1 /usr/bin/python3 /ruta/completa/update_nvd_db.py >> /var/log/nvd_update.log 2>&1
```

---

# 📁 Estructura del proyecto

```bash
.
├── docker-compose.yml          # Servicios Docker
├── Modelfile                   # Definición del modelo personalizado (auditor-seguridad)
├── requirements.txt            # Dependencias Python
├── update_nvd_db.py            # Script de sincronización de la base NVD
├── analizador_rag_cli.py       # Script principal de análisis (RAG + PDF)
└── README.md                   # Este archivo
```

---

# 📄 Licencia

Este proyecto se distribuye bajo la licencia MIT.
Nota: Los modelos descargados y la base de datos NVD tienen sus propias licencias. Consulta los sitios oficiales de Meta, DeepSeek y NIST.

---

# 🤝 Contribuciones

¡Todo aporte es bienvenido!
Abre un issue si encuentras errores o propones mejoras. Los PR son revisados con gusto.

---

Hecho con 🧠 + ❤️ para mantener tu código seguro y privado.

---

## Refactorización automática realizada por opencode

### Archivos modificados

| Archivo | Cambio |
|---|---|
| `config.py` | **Nuevo** — módulo de configuración centralizada que lee de variables de entorno con `load_dotenv()`. Contiene todas las constantes y helpers compartidos. |
| `.env` / `.env.example` | **Nuevos** — archivos de configuración con todas las variables extraídas. |
| `analizador_rag_cli.py` | Extraídas ~20 constantes a `config.py`; eliminada función `fetch_cves_recent` duplicada; refactorizado `_parse_and_store_findings` con `_FIELD_MAP`; extraído helper `_confirmar()` del manejador de señales; eliminada variable muerta `QUEUE_MODE`; eliminado argumento `--analisis-id` no usado. |
| `update_nvd_db.py` | Extraídas ~10 constantes a `config.py`; eliminadas funciones duplicadas (`fetch_cves_recent`, `generate_embeddings_batch`); extraído helper `check_embedding_endpoint()`. |
| `index_exploitdb.py` | Extraídas ~8 constantes a `config.py`; eliminada función duplicada `generate_embeddings_batch` y lógica de paginación de ChromaDB. |
| `mongo_integration.py` | Extraídas 3 constantes (`MONGO_URI`, `MONGO_DATABASE_NAME`, `MONGO_TIMEOUT_MS`) a `config.py`. |
| `tasks.py` | Eliminados imports no usados (`sys`, `time`, `json`); eliminada variable muerta `archivos_con_hallazgos`; constantes desde `config.py`. |
| `Dockerfile.worker` | Agregada copia de `config.py` al contenedor. |
| `.gitignore` | Agregada entrada para `.env`. |
| `requirements.txt` | Agregado `python-dotenv`. |

### Variables trasladadas a `.env`

| Nombre original | Variable de entorno | Archivos afectados |
|---|---|---|
| `MODEL` → | `ANALYZER_MODEL` | analizador_rag_cli.py, config.py |
| `EMBED_MODEL` → | `EMBEDDING_MODEL` | analizador_rag_cli.py, update_nvd_db.py, index_exploitdb.py, config.py |
| `OLLAMA_URL` → | `OLLAMA_API_URL` / `OLLAMA_BASE_URL` | analizador_rag_cli.py, update_nvd_db.py, index_exploitdb.py, config.py |
| `CHROMA_HOST` / `CHROMA_PORT` | `CHROMA_HOST` / `CHROMA_PORT` | Todos los .py |
| `COLLECTION_NAME` → | `CHROMA_NVD_COLLECTION` | analizador_rag_cli.py, update_nvd_db.py, config.py |
| `exploitdb_exploits` → | `CHROMA_EXPLOIT_COLLECTION` | analizador_rag_cli.py, index_exploitdb.py, config.py |
| `LAST_UPDATE_FILE` → | `NVD_LAST_UPDATE_FILE` | analizador_rag_cli.py, update_nvd_db.py, config.py |
| `CHUNK_SIZE` → | `ANALYSIS_CHUNK_SIZE` | analizador_rag_cli.py, tasks.py, config.py |
| `REPORT_DIR` → | `REPORT_OUTPUT_DIR` | analizador_rag_cli.py, tasks.py, config.py |
| `TEMPERATURE` → | `LLM_TEMPERATURE` | analizador_rag_cli.py, config.py |
| `BATCH_SIZE` (update_nvd) → | `NVD_BATCH_SIZE` | update_nvd_db.py, config.py |
| `BATCH_SIZE` (exploitdb) → | `EXPLOIT_BATCH_SIZE` | index_exploitdb.py, config.py |
| `EMBED_TIMEOUT` → | `EMBED_BATCH_TIMEOUT` | update_nvd_db.py, index_exploitdb.py, config.py |
| `MAX_RETRIES` → | `EMBED_MAX_RETRIES` | update_nvd_db.py, index_exploitdb.py, config.py |
| `API_TIMEOUT` → | `NVD_API_TIMEOUT` | update_nvd_db.py, config.py |
| `MONGO_URI` (default) | `MONGO_URI` | mongo_integration.py, config.py |
| `MONGO_DB` → | `MONGO_DATABASE_NAME` | mongo_integration.py, config.py |
| `EXPLOITDB_REPO` → | `EXPLOITDB_REPO_URL` | index_exploitdb.py, config.py |
| `EXPLOITDB_DIR` → | `EXPLOITDB_LOCAL_DIR` | index_exploitdb.py, config.py |
| `MAX_TEXT_LENGTH` → | `EXPLOIT_MAX_TEXT_LENGTH` | index_exploitdb.py, config.py |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | (ya eran env vars, se consolidaron en config.py) | tasks.py, config.py |

### Fragmentos de código redundante refactorizados

1. **`fetch_cves_recent`** — función duplicada en `analizador_rag_cli.py` y `update_nvd_db.py`. Extraída a `config.py` como helper compartido.

2. **`generate_embeddings_batch`** — función duplicada en `update_nvd_db.py` e `index_exploitdb.py`. Extraída a `config.py` con parámetros configurables.

3. **Paginación de ChromaDB** — lógica de "leer todos los IDs existentes paginando" duplicada en `update_nvd_db.py` e `index_exploitdb.py`. Extraída a `config.get_chroma_existing_ids()`.

4. **Parseo de hallazgos** — la cadena de `if/elif` con 6 campos repetidos en `_parse_and_store_findings` fue reemplazada por un mapa `_FIELD_MAP` con iteración.

5. **Confirmación de entrada** — lógica de `input("...")` + bucle while con validación duplicada 3 veces en `signal_handler`. Extraída a `_confirmar()`.

6. **Generación de PDF** — patrón repetitivo `story.append(Paragraph(...))` / `story.append(Spacer(...))` extraído a `_add_heading()`.

7. **Variables muertas eliminadas**: `QUEUE_MODE` en `analizador_rag_cli.py`, `archivos_con_hallazgos` en `tasks.py`. Imports no usados: `sys`, `time`, `json` en `tasks.py`.

### Pasos a seguir por el desarrollador

1. **Configurar el archivo `.env`**: copia `.env.example` a `.env` (o renombra el `.env` existente) y ajusta los valores según tu entorno (contraseñas, hosts, puertos, etc.).

2. **Instalar dependencias**: ejecuta `pip install -r requirements.txt` para instalar `python-dotenv` y el resto de dependencias.

3. **Verificar las variables de entorno**: todas las referencias usan `os.getenv` con valores por defecto en `config.py`. No debería ser necesario configurar nada para que funcione out-of-the-box, pero para personalización, edita `.env`.

4. **Ejecutar los tests**: si existen tests, ejecútalos para validar la refactorización:
   ```bash
   python3 -c "import config; print('config.py OK')"
   python3 -m py_compile analizador_rag_cli.py update_nvd_db.py index_exploitdb.py mongo_integration.py tasks.py
   ```

5. **No commitees `.env`**: el archivo `.env` ya está en `.gitignore`. Solo commitea `.env.example` como plantilla.

