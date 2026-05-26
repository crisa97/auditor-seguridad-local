import os
import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Ollama ──────────────────────────────────────
ANALYZER_MODEL = os.getenv("ANALYZER_MODEL", "auditor-seguridad")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_NUM_CTX = int(os.getenv("LLM_NUM_CTX", "8192"))
LLM_NUM_PREDICT = int(os.getenv("LLM_NUM_PREDICT", "2048"))

# ── ChromaDB ────────────────────────────────────
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = os.getenv("CHROMA_PORT", "8001")
CHROMA_NVD_COLLECTION = os.getenv("CHROMA_NVD_COLLECTION", "nvd_vulnerabilities")
CHROMA_EXPLOIT_COLLECTION = os.getenv("CHROMA_EXPLOIT_COLLECTION", "exploitdb_exploits")
CHROMA_PAGE_SIZE = int(os.getenv("CHROMA_PAGE_SIZE", "1000"))
CHROMA_QUERY_RESULTS = int(os.getenv("CHROMA_QUERY_RESULTS", "3"))

# ── NVD API ─────────────────────────────────────
NVD_API_BASE_URL = os.getenv("NVD_API_BASE_URL",
                              "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_DAYS_BACK = int(os.getenv("NVD_DAYS_BACK", "90"))
NVD_PAGE_SIZE = int(os.getenv("NVD_PAGE_SIZE", "2000"))
NVD_API_TIMEOUT = int(os.getenv("NVD_API_TIMEOUT", "30"))
NVD_API_DELAY = float(os.getenv("NVD_API_DELAY", "0.6"))
NVD_LAST_UPDATE_FILE = os.getenv("NVD_LAST_UPDATE_FILE", "last_nvd_update.txt")
NVD_UPDATE_INTERVAL_DAYS = int(os.getenv("NVD_UPDATE_INTERVAL_DAYS", "7"))

# ── Embeddings ──────────────────────────────────
EMBED_BATCH_TIMEOUT = int(os.getenv("EMBED_BATCH_TIMEOUT", "300"))
EMBED_MAX_RETRIES = int(os.getenv("EMBED_MAX_RETRIES", "2"))
EMBED_SINGLE_TIMEOUT = int(os.getenv("EMBED_SINGLE_TIMEOUT", "60"))

# ── Análisis ────────────────────────────────────
ANALYSIS_CHUNK_SIZE = int(os.getenv("ANALYSIS_CHUNK_SIZE", "8000"))
ANALYSIS_QUERY_LENGTH = int(os.getenv("ANALYSIS_QUERY_LENGTH", "500"))
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", "reportes")

# ── MongoDB ─────────────────────────────────────
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://admin:seguridad_local_pass@localhost:27017/vulnerabilidades?authSource=admin"
)
MONGO_DATABASE_NAME = os.getenv("MONGO_DATABASE_NAME", "vulnerabilidades")
MONGO_TIMEOUT_MS = int(os.getenv("MONGO_TIMEOUT_MS", "5000"))

# ── ExploitDB ───────────────────────────────────
EXPLOITDB_REPO_URL = os.getenv("EXPLOITDB_REPO_URL",
                                "https://gitlab.com/exploit-database/exploitdb.git")
EXPLOITDB_LOCAL_DIR = os.getenv("EXPLOITDB_LOCAL_DIR", "./exploitdb-local")
EXPLOIT_BATCH_SIZE = int(os.getenv("EXPLOIT_BATCH_SIZE", "10"))
EXPLOIT_MAX_TEXT_LENGTH = int(os.getenv("EXPLOIT_MAX_TEXT_LENGTH", "2000"))

# ── NVD batch ───────────────────────────────────
NVD_BATCH_SIZE = int(os.getenv("NVD_BATCH_SIZE", "200"))

# ── Celery ──────────────────────────────────────
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")


# ── Helpers compartidos ─────────────────────────

def get_nvd_date_range(days=None):
    if days is None:
        days = NVD_DAYS_BACK
    end = datetime.datetime.now(datetime.timezone.utc)
    start = end - datetime.timedelta(days=days)
    return (start.strftime('%Y-%m-%dT%H:%M:%S.000'),
            end.strftime('%Y-%m-%dT%H:%M:%S.000'))


def nvd_api_params(start_str, end_str, start_index=0):
    return {
        'pubStartDate': start_str,
        'pubEndDate': end_str,
        'resultsPerPage': NVD_PAGE_SIZE,
        'startIndex': start_index,
    }


def fetch_cves_recent(days=None):
    if days is None:
        days = NVD_DAYS_BACK
    start_str, end_str = get_nvd_date_range(days)
    params = nvd_api_params(start_str, end_str)
    all_cves = []
    while True:
        try:
            resp = __import__('requests').get(NVD_API_BASE_URL, params=params,
                                              timeout=NVD_API_TIMEOUT)
            if resp.status_code == 404:
                break
            resp.raise_for_status()
            data = resp.json()
            for vuln in data.get('vulnerabilities', []):
                cve = vuln['cve']
                desc = next(
                    (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
                    "Sin descripción"
                )
                metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])
                cvss_data = metrics[0].get('cvssData', {}) if metrics else {}
                all_cves.append({
                    'id': cve['id'],
                    'description': desc,
                    'severity': cvss_data.get('baseSeverity', 'N/A'),
                    'score': cvss_data.get('baseScore', 'N/A'),
                })
            total = data.get('totalResults', 0)
            if len(all_cves) >= total:
                break
            params['startIndex'] = (data.get('startIndex', 0) +
                                    data.get('resultsPerPage', 0))
            __import__('time').sleep(NVD_API_DELAY)
        except Exception as e:
            print(f"Error al conectar con la API NVD: {e}")
            break
    return all_cves


def generate_embeddings_batch(texts, model=None, timeout=None, max_retries=None):
    if model is None:
        model = EMBEDDING_MODEL
    if timeout is None:
        timeout = EMBED_BATCH_TIMEOUT
    if max_retries is None:
        max_retries = EMBED_MAX_RETRIES

    import requests
    import time
    payload = {"model": model, "input": texts}
    for attempt in range(max_retries):
        try:
            r = requests.post(f"{OLLAMA_BASE_URL}/api/embed", json=payload,
                              timeout=timeout)
            r.raise_for_status()
            data = r.json()
            if "embeddings" in data:
                return data["embeddings"]
            else:
                print(f"Intento {attempt+1}: respuesta sin 'embeddings'.")
        except requests.Timeout:
            print(f"Intento {attempt+1}: timeout ({timeout}s).", end="")
            if attempt < max_retries - 1:
                print(" Reintentando...")
                time.sleep(5)
            else:
                print(" No más reintentos.")
        except Exception as e:
            print(f"Intento {attempt+1}: error {e}")
            break
    return None


def generate_single_embedding(text, model=None, timeout=None):
    if model is None:
        model = EMBEDDING_MODEL
    if timeout is None:
        timeout = EMBED_SINGLE_TIMEOUT
    payload = {"model": model, "input": [text]}
    try:
        r = __import__('requests').post(f"{OLLAMA_API_URL}/embed", json=payload,
                                        timeout=timeout)
        r.raise_for_status()
        return r.json()["embeddings"][0]
    except Exception as e:
        print(f"Error generando embedding: {e}")
        return None


def get_chroma_existing_ids(collection):
    existing_ids = set()
    offset = 0
    while True:
        batch = collection.get(limit=CHROMA_PAGE_SIZE, offset=offset, include=[])
        if not batch['ids']:
            break
        existing_ids.update(batch['ids'])
        offset += len(batch['ids'])
    return existing_ids


def get_last_update_date(filepath=None):
    if filepath is None:
        filepath = NVD_LAST_UPDATE_FILE
    if not os.path.exists(filepath):
        return None
    with open(filepath) as f:
        return f.read().strip()


def set_last_update_date(date_str=None, filepath=None):
    if date_str is None:
        date_str = datetime.date.today().isoformat()
    if filepath is None:
        filepath = NVD_LAST_UPDATE_FILE
    with open(filepath, "w") as f:
        f.write(date_str)
