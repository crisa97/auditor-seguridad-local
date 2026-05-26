"""
Wrapper backward-compatible que re-exporta desde la nueva arquitectura.
"""
import sys
sys.path.insert(0, "/home/crisa/seguridad-local")

from src.infrastructure.config import settings

# ── Ollama ──
ANALYZER_MODEL = settings.analyzer_model
EMBEDDING_MODEL = settings.embedding_model
OLLAMA_API_URL = settings.ollama_api_url
OLLAMA_BASE_URL = settings.ollama_base_url
LLM_TEMPERATURE = settings.llm_temperature
LLM_NUM_CTX = settings.llm_num_ctx
LLM_NUM_PREDICT = settings.llm_num_predict

# ── ChromaDB ──
CHROMA_HOST = settings.chroma_host
CHROMA_PORT = settings.chroma_port
CHROMA_NVD_COLLECTION = settings.chroma_nvd_collection
CHROMA_EXPLOIT_COLLECTION = settings.chroma_exploit_collection
CHROMA_PAGE_SIZE = settings.chroma_page_size
CHROMA_QUERY_RESULTS = settings.chroma_query_results

# ── NVD API ──
NVD_API_BASE_URL = settings.nvd_api_base_url
NVD_DAYS_BACK = settings.nvd_days_back
NVD_PAGE_SIZE = settings.nvd_page_size
NVD_API_TIMEOUT = settings.nvd_api_timeout
NVD_API_DELAY = settings.nvd_api_delay
NVD_LAST_UPDATE_FILE = settings.nvd_last_update_file
NVD_UPDATE_INTERVAL_DAYS = settings.nvd_update_interval_days

# ── Embeddings ──
EMBED_BATCH_TIMEOUT = settings.embed_batch_timeout
EMBED_MAX_RETRIES = settings.embed_max_retries
EMBED_SINGLE_TIMEOUT = settings.embed_single_timeout

# ── Analisis ──
ANALYSIS_CHUNK_SIZE = settings.analysis_chunk_size
ANALYSIS_QUERY_LENGTH = settings.analysis_query_length
REPORT_OUTPUT_DIR = settings.report_output_dir

# ── MongoDB ──
MONGO_URI = settings.mongo_uri
MONGO_DATABASE_NAME = settings.mongo_database
MONGO_TIMEOUT_MS = settings.mongo_timeout_ms

# ── ExploitDB ──
EXPLOITDB_REPO_URL = settings.exploitdb_repo_url
EXPLOITDB_LOCAL_DIR = settings.exploitdb_local_dir
EXPLOIT_BATCH_SIZE = settings.exploit_batch_size
EXPLOIT_MAX_TEXT_LENGTH = settings.exploit_max_text_length

# ── NVD batch ──
NVD_BATCH_SIZE = settings.nvd_batch_size

# ── Celery ──
CELERY_BROKER_URL = settings.celery_broker_url
CELERY_RESULT_BACKEND = settings.celery_result_backend

# ── Validacion / API Keys ──
DB_URL = settings.db_url
API_KEY_SALT = settings.api_key_salt
VALIDATION_SERVICE_URL = settings.validation_service_url
OLLAMA_TIMEOUT = settings.ollama_timeout

# ── Helpers ──
def get_nvd_date_range(days=None):
    return settings.get_nvd_date_range(days)

def nvd_api_params(start_str, end_str, start_index=0):
    return {
        'pubStartDate': start_str,
        'pubEndDate': end_str,
        'resultsPerPage': settings.nvd_page_size,
        'startIndex': start_index,
    }

def fetch_cves_recent(days=None):
    return _fetch_cves_recent_fallback(days)

def _fetch_cves_recent_fallback(days=None):
    import datetime, requests, time
    if days is None:
        days = settings.nvd_days_back
    start_str, end_str = settings.get_nvd_date_range(days)
    params = {
        'pubStartDate': start_str,
        'pubEndDate': end_str,
        'resultsPerPage': settings.nvd_page_size,
        'startIndex': 0,
    }
    all_cves = []
    while True:
        try:
            resp = requests.get(NVD_API_BASE_URL, params=params, timeout=NVD_API_TIMEOUT)
            if resp.status_code == 404:
                break
            resp.raise_for_status()
            data = resp.json()
            for vuln in data.get('vulnerabilities', []):
                cve = vuln['cve']
                desc = next(
                    (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
                    "Sin descripcion"
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
            params['startIndex'] = data.get('startIndex', 0) + data.get('resultsPerPage', 0)
            time.sleep(NVD_API_DELAY)
        except Exception as e:
            print(f"Error al conectar con la API NVD: {e}")
            break
    return all_cves

def generate_embeddings_batch(texts, model=None, timeout=None, max_retries=None):
    from src.adapters.ollama.embedding_service import OllamaEmbeddingService
    svc = OllamaEmbeddingService()
    return svc.generate_batch(texts)

def generate_single_embedding(text, model=None, timeout=None):
    from src.adapters.ollama.embedding_service import OllamaEmbeddingService
    svc = OllamaEmbeddingService()
    return svc.generate(text)

def get_chroma_existing_ids(collection):
    offset = 0
    existing_ids = set()
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
    import os
    if not os.path.exists(filepath):
        return None
    with open(filepath) as f:
        return f.read().strip()

def set_last_update_date(date_str=None, filepath=None):
    import datetime
    if date_str is None:
        date_str = datetime.date.today().isoformat()
    if filepath is None:
        filepath = NVD_LAST_UPDATE_FILE
    with open(filepath, "w") as f:
        f.write(date_str)
