# Guía de Ejecución — seguridad-local

## Requisitos

- Docker + Docker Compose
- Python 3.10+
- 8 GB RAM mínimo (16 GB recomendado)
- Git

---

## 1. Clonar y Configurar

```bash
git clone <repo> && cd seguridad-local
cp .env.example .env
```

Editar `.env` con los valores reales (hosts, puertos, credenciales).  
Ver `.env.example` para la lista completa de variables.

---

## 2. Iniciar Infraestructura (Docker)

```bash
docker compose up -d
```

Esto inicia 8 servicios:

| Servicio | Puerto | Inicio |
|---|---|---|
| ollama | 11434 | Automático |
| ollama-init | — | One-shot (pull modelos, crear `auditor-seguridad`) |
| chromadb | 8001 | Automático |
| mongodb | 27017 | Automático |
| postgres | 5432 | Automático (solo localhost) |
| redis | 6379 | Automático |
| celery-worker | — | Automático |
| validation-service | 8000 | Automático (solo localhost, 2 réplicas) |
| open-webui | 3000 | Automático (solo localhost) |

Esperar a que `ollama-init` termine (descarga modelos ~10-20 GB).

Verificar:

```bash
docker compose logs ollama-init -f
```

---

## 3. Instalar Dependencias Python

```bash
pip install -r requirements.txt
```

(Opcional) Usar virtualenv:

```bash
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

---

## 4. Inicializar Base de Datos

```bash
python3 database/init_db.py
```

Crea las tablas en PostgreSQL: `conocimiento_validado`, `pendiente_validacion`, `api_keys`.

---

## 5. Sincronizar Bases de Vulnerabilidades

### NVD (CVEs)

```bash
python3 update_nvd_db.py
```

Descarga CVEs de los últimos 90 días (configurable vía `NVD_DAYS_BACK`).  
Los almacena en MongoDB + indexa embeddings en ChromaDB.

### ExploitDB

```bash
python3 index_exploitdb.py
```

Clona el repositorio de ExploitDB y lo indexa en MongoDB + ChromaDB.

---

## 6. Usar el Analizador

### Análisis Directo (sincrónico)

```bash
python3 analizador_rag_cli.py /ruta/al/proyecto
```

Con API key:

```bash
python3 analizador_rag_cli.py --api-key "sk-..." /ruta/al/proyecto
```

Enviando resultados al servicio de validación:

```bash
python3 analizador_rag_cli.py \
  --api-key "sk-..." \
  --enviar "http://localhost:8000" \
  /ruta/al/proyecto
```

### Análisis por Cola (Celery — asíncrono)

```bash
python3 analizador_rag_cli.py --queue /ruta/al/proyecto
python3 analizador_rag_cli.py --status <task_id>
python3 analizador_rag_cli.py --list
```

### Forzar Actualización NVD

```bash
python3 analizador_rag_cli.py --update-nvd /ruta/al/proyecto
```

Los reportes se generan en el directorio configurado (`REPORT_OUTPUT_DIR`, por defecto `reportes/`).

---

## 7. Generar API Keys

```bash
# Generar y guardar en PostgreSQL
python3 generar_apikey.py --cliente "Cliente ACME" --permisos "rag:leer" --dias 365

# Solo generar (sin BD)
python3 generar_apikey.py --cliente "Test" --solo-generar
```

---

## 8. Servicio de Validación (FastAPI)

Ya corre en Docker (puerto 8000). Para ejecutar directamente:

```bash
uvicorn validation_service:app --host 0.0.0.0 --port 8000
```

Endpoints:

| Método | Ruta |
|---|---|
| GET | `http://localhost:8000/api/v1/health` |
| POST | `http://localhost:8000/api/v1/rag/consultar` |
| GET | `http://localhost:8000/api/v1/docs` (Swagger) |

---

## 9. Open WebUI

Acceder en `http://localhost:3000` (o `https://seguridad.local` con Nginx).  
Configurar en Open WebUI: Settings → Connections → Ollama → `http://ollama:11434`.

---

## 10. Ejecutar Tests

```bash
python3 -m pytest tests/ -v
```

---

## 11. Despliegue con Nginx (Opcional)

```bash
sudo cp nginx/openwebui.conf /etc/nginx/sites-available/openwebui
sudo ln -s /etc/nginx/sites-available/openwebui /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Asegurar que `seguridad.local` apunte a `127.0.0.1` en `/etc/hosts`.

---

## 12. Construir Imágenes Docker (si se modifican)

```bash
docker build -f Dockerfile.validation -t validation-service .
docker build -f Dockerfile.worker -t celery-worker .
docker build -f Dockerfile.openwebui -t open-webui-custom .
```

---

## Notas Importantes

- **ollama-init** se ejecuta una sola vez. Si falla, reiniciar con: `docker compose up -d ollama-init`
- Los modelos requieren ~10-20 GB de descarga inicial
- No editar archivos dentro de `src/` desde los wrappers raíz — editar en `src/`
- Todas las contraseñas por defecto están en `docker-compose.yml` — cambiarlas para producción
- Los puertos de PostgreSQL, Redis, validation-service y Open WebUI están vinculados solo a `127.0.0.1` por seguridad
- nomic-embed-text necesita ~274 MB, deepseek-coder-v2:16b necesita ~9 GB
