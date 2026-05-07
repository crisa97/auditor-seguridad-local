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

