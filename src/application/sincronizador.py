import datetime
import logging
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

from src.domain.models import Cve, Exploit, OwaspTop10Entry
from src.ports.repositories import ICveRepository, IExploitRepository, IOwaspTop10Repository
from src.ports.services import IEmbeddingService, IVectorStore
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


class SincronizarNvd:
    def __init__(
        self,
        cve_repo: ICveRepository,
        embed: IEmbeddingService,
        vector_store: IVectorStore,
    ):
        self._cve_repo = cve_repo
        self._embed = embed
        self._vector_store = vector_store

    def _check_embed_endpoint(self) -> bool:
        try:
            r = requests.post(
                f"{settings.ollama_base_url}/api/embed",
                json={"model": settings.embedding_model, "input": ["test"]},
                timeout=60,
            )
            return r.status_code == 200 and "embeddings" in r.json()
        except Exception as e:
            logger.warning("Error checking embed endpoint: %s", e)
            return False

    def execute(self) -> None:
        if not self._check_embed_endpoint():
            print("El endpoint /api/embed no respondio correctamente.")
            return

        print("Leyendo CVEs ya almacenadas en ChromaDB...")
        existing_ids = self._vector_store.get_existing_ids(settings.chroma_nvd_collection)
        print(f"Ya hay {len(existing_ids)} CVEs en ChromaDB.")

        print("Descargando CVEs recientes...")
        cves = self._fetch_cves_recent()

        new_cves = [cve for cve in cves if cve['id'] not in existing_ids]
        if not new_cves:
            print("Todas las CVEs ya estaban en la base.")
            settings.set_last_update_date()
            return

        print(f"Se anadiran {len(new_cves)} CVEs nuevas de {len(cves)} totales.")

        print("Guardando en MongoDB...")
        try:
            self._cve_repo.store_bulk([
                Cve(id=c['id'], description=c['description'],
                    severity=c['severity'], score=c['score'])
                for c in new_cves
            ])
            print(f"   OK {len(new_cves)} CVEs almacenadas en MongoDB.")
        except Exception as e:
            print(f"   Error al guardar en MongoDB: {e}")

        docs = []
        ids = []
        for cve in new_cves:
            doc = (f"CVE ID: {cve['id']}\n"
                   f"Severidad: {cve['severity']} (CVSS: {cve['score']})\n"
                   f"Descripcion: {cve['description']}")
            docs.append(doc)
            ids.append(cve['id'])

        total = len(docs)
        print(f"Generando embeddings en lotes de {settings.nvd_batch_size}...")

        for start in range(0, total, settings.nvd_batch_size):
            end = min(start + settings.nvd_batch_size, total)
            batch_docs = docs[start:end]
            batch_ids = ids[start:end]

            embeddings = self._embed.generate_batch(batch_docs)
            if embeddings is None:
                print(f"Fallo en lote {start // settings.nvd_batch_size + 1}. Abortando.")
                return

            try:
                self._vector_store.upsert(
                    settings.chroma_nvd_collection,
                    ids=batch_ids,
                    documents=batch_docs,
                    embeddings=embeddings,
                )
                print(f"   OK Lote {start // settings.nvd_batch_size + 1} ({start + 1}-{end}/{total}) insertado.")
            except Exception as e:
                print(f"Error al insertar lote: {e}")
                return

        settings.set_last_update_date()
        print(f"Base actualizada. Total CVEs ahora: {len(existing_ids) + total}.")

    def _fetch_cves_recent(self, days: Optional[int] = None) -> list[dict]:
        if days is None:
            days = settings.nvd_days_back
        start_str, end_str = settings.get_nvd_date_range(days)
        params = {
            'pubStartDate': start_str,
            'pubEndDate': end_str,
            'resultsPerPage': settings.nvd_page_size,
            'startIndex': 0,
        }
        headers = {}
        if settings.nvd_api_key:
            headers['apiKey'] = settings.nvd_api_key
        all_cves: list[dict] = []
        while True:
            try:
                resp = requests.get(
                    settings.nvd_api_base_url,
                    params=params,
                    headers=headers or None,
                    timeout=settings.nvd_api_timeout,
                )
                if resp.status_code == 404:
                    break
                resp.raise_for_status()
                data = resp.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln['cve']
                    desc = next(
                        (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
                        "Sin descripcion",
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
                params['startIndex'] = (
                    data.get('startIndex', 0) + data.get('resultsPerPage', 0)
                )
                time.sleep(settings.nvd_api_delay)
            except Exception as e:
                print(f"Error al conectar con la API NVD: {e}")
                break
        return all_cves


class IndexarExploitDb:
    def __init__(
        self,
        exploit_repo: IExploitRepository,
        embed: IEmbeddingService,
        vector_store: IVectorStore,
    ):
        self._exploit_repo = exploit_repo
        self._embed = embed
        self._vector_store = vector_store

    def _clone_or_update_repo(self) -> None:
        if not os.path.exists(settings.exploitdb_local_dir):
            print(f"Clonando {settings.exploitdb_repo_url} ...")
            subprocess.run(
                ["git", "clone", "--depth", "1", settings.exploitdb_repo_url, settings.exploitdb_local_dir],
                check=True,
            )
        else:
            print("Actualizando repositorio local de ExploitDB...")
            subprocess.run(["git", "-C", settings.exploitdb_local_dir, "pull"], check=True)

    TEXT_EXTENSIONS = frozenset({
        ".py", ".rb", ".php", ".pl", ".pm", ".c", ".cpp", ".h", ".hpp",
        ".java", ".js", ".ts", ".go", ".rs", ".swift", ".kt", ".scala",
        ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
        ".txt", ".md", ".rst", ".html", ".htm", ".xml", ".json", ".yaml",
        ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
        ".sql", ".css", ".scss", ".less", ".vue", ".jsx", ".tsx",
        ".asm", ".s", ".lua", ".tcl", ".erl", ".hrl", ".ex", ".exs",
        ".clj", ".cljs", ".edn", ".coffee", ".dart", ".jl",
        ".cs", ".fs", ".fsx", ".vb", ".vbs",
        ".r", ".rmd", ".m", ".mm",
        ".gradle", ".maven", ".pom", ".sbt", ".cabal",
        ".cmake", ".mk", ".makefile", ".dockerfile",
        ".htaccess", ".htpasswd",
        ".csv", ".tsv", ".log",
        ".tex", ".bib",
    })

    def _parse_files(self) -> list[dict]:
        exploits_dir = os.path.join(settings.exploitdb_local_dir, "exploits")
        if not os.path.isdir(exploits_dir):
            raise FileNotFoundError(f"No se encontro la carpeta {exploits_dir}")

        documents: list[dict] = []
        for root, dirs, files in os.walk(exploits_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in self.TEXT_EXTENSIONS:
                    logger.debug("Saltando archivo binario/sin texto: %s", file)
                    continue
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    if text.strip():
                        text = text[:settings.exploit_max_text_length]
                        rel_path = os.path.relpath(path, settings.exploitdb_local_dir)
                        documents.append({
                            "id": rel_path.replace("/", "_").replace("\\", "_"),
                            "path": rel_path,
                            "text": text,
                        })
                except Exception as e:
                    logger.warning("No se pudo leer archivo exploit %s: %s", path, e)
        return documents

    def execute(self) -> None:
        print("=== Indexando ExploitDB en MongoDB + ChromaDB ===")

        self._clone_or_update_repo()

        print("Extrayendo texto de los exploits...")
        docs = self._parse_files()
        print(f"Se encontraron {len(docs)} exploits.")

        if not docs:
            print("No se encontraron documentos. Abortando.")
            return

        print("Guardando en MongoDB...")
        try:
            self._exploit_repo.store_bulk([
                Exploit(id=d['id'], path=d['path'], text=d['text'])
                for d in docs
            ])
            print(f"   OK {len(docs)} exploits almacenados en MongoDB.")
        except Exception as e:
            print(f"   Error al guardar en MongoDB: {e}")

        existing_ids = self._vector_store.get_existing_ids(settings.chroma_exploit_collection)
        print(f"Ya existen {len(existing_ids)} exploits en ChromaDB.")

        new_docs = [d for d in docs if d['id'] not in existing_ids]
        if not new_docs:
            print("Todos los exploits ya estaban indexados.")
            return

        print(f"Se indexaran {len(new_docs)} nuevos exploits.")

        batch_size = settings.exploit_batch_size
        total = len(new_docs)

        def _embed_batch(start: int, end: int) -> tuple:
            batch = new_docs[start:end]
            ids, texts, paths = [], [], []
            for d in batch:
                t = (d['text'] or "").replace("\x00", "").strip()
                if t:
                    ids.append(d['id'])
                    texts.append(t)
                    paths.append(d['path'])
            if not texts:
                return [], [], [], []
            embeddings = self._embed.generate_batch(texts)
            if embeddings is None:
                raise RuntimeError(f"Fallo embedding lote {start // batch_size + 1}")
            return ids, texts, paths, embeddings

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            for start in range(0, total, batch_size):
                end = min(start + batch_size, total)
                future = pool.submit(_embed_batch, start, end)
                futures[future] = (start, end)

            for future in as_completed(futures):
                start, end = futures.pop(future)
                ids, texts, paths, embeddings = future.result()
                try:
                    self._vector_store.upsert(
                        settings.chroma_exploit_collection,
                        ids=ids, documents=texts,
                        embeddings=embeddings,
                        metadatas=[{"path": p} for p in paths],
                    )
                    print(f"   OK Lote {start // batch_size + 1} ({start + 1}-{end}/{total}) insertado.")
                except Exception as e:
                    print(f"Error en lote {start // batch_size + 1}: {e}")
                    return

        print(f"Indexacion completada. Total: {len(existing_ids) + total} exploits.")


class IndexarOwaspTop10:
    def __init__(
        self,
        owasp_repo: IOwaspTop10Repository,
        embed: IEmbeddingService,
        vector_store: IVectorStore,
    ):
        self._owasp_repo = owasp_repo
        self._embed = embed
        self._vector_store = vector_store

    def _clone_or_update_repo(self) -> None:
        if not os.path.exists(settings.owasp_local_dir):
            print(f"Clonando {settings.owasp_repo_url} ...")
            subprocess.run(
                ["git", "clone", "--depth", "1", settings.owasp_repo_url, settings.owasp_local_dir],
                check=True,
            )
        else:
            print("Actualizando repositorio local de OWASP Top10...")
            subprocess.run(["git", "-C", settings.owasp_local_dir, "pull"], check=True)

    def _parse_files(self) -> list[dict]:
        docs_dir = os.path.join(settings.owasp_local_dir, "2025", "docs", "en")
        if not os.path.isdir(docs_dir):
            raise FileNotFoundError(f"No se encontro la carpeta {docs_dir}")

        CATEGORY_MAP = {
            "0x00": "introduction",
            "0x01": "about_owasp",
            "0x02": "risk_methodology",
            "0x03": "appsec_program",
            "A01": "broken_access_control",
            "A02": "security_misconfiguration",
            "A03": "supply_chain",
            "A04": "cryptographic_failures",
            "A05": "injection",
            "A06": "insecure_design",
            "A07": "authentication_failures",
            "A08": "integrity_failures",
            "A09": "logging_failures",
            "A10": "exceptional_conditions",
            "X01": "next_steps",
        }

        documents: list[dict] = []
        for fname in sorted(os.listdir(docs_dir)):
            if not fname.endswith(".md"):
                continue
            path = os.path.join(docs_dir, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                if not text.strip():
                    continue

                prefix = fname.split("_")[0] if "_" in fname else fname.replace(".md", "")
                category = CATEGORY_MAP.get(prefix, fname.replace(".md", ""))

                title = category.replace("_", " ").title()
                for line in text.split("\n"):
                    if line.startswith("# ") and len(line) > 2:
                        title = line[2:].strip()
                        break

                risk_rank = ""
                if fname.startswith("A"):
                    risk_rank = fname[1:3]

                doc_id = f"owasp_2025_{prefix.lower()}"
                documents.append({
                    "id": doc_id,
                    "category": category,
                    "title": title,
                    "content": text[:settings.owasp_max_text_length],
                    "risk_rank": risk_rank,
                    "cwes": "",
                })
            except Exception as e:
                logger.warning("No se pudo leer archivo OWASP %s: %s", path, e)
        return documents

    def execute(self) -> None:
        print("=== Indexando OWASP Top 10 2025 en MongoDB + ChromaDB ===")

        self._clone_or_update_repo()

        print("Extrayendo documentos OWASP Top 10...")
        docs = self._parse_files()
        print(f"Se encontraron {len(docs)} documentos.")

        if not docs:
            print("No se encontraron documentos. Abortando.")
            return

        print("Guardando en MongoDB...")
        try:
            self._owasp_repo.store_bulk([
                OwaspTop10Entry(
                    id=d['id'],
                    category=d['category'],
                    title=d['title'],
                    content=d['content'],
                    risk_rank=d['risk_rank'],
                    cwes=d['cwes'],
                )
                for d in docs
            ])
            print(f"   OK {len(docs)} documentos almacenados en MongoDB.")
        except Exception as e:
            print(f"   Error al guardar en MongoDB: {e}")

        existing_ids = self._vector_store.get_existing_ids(settings.chroma_owasp_collection)
        print(f"Ya existen {len(existing_ids)} documentos en ChromaDB.")

        new_docs = [d for d in docs if d['id'] not in existing_ids]
        if not new_docs:
            print("Todos los documentos ya estaban indexados.")
            return

        print(f"Se indexaran {len(new_docs)} nuevos documentos.")

        batch_size = settings.owasp_batch_size
        total = len(new_docs)

        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            batch = new_docs[start:end]
            ids = [d['id'] for d in batch]
            texts = [d['content'] for d in batch]
            metadatas = [
                {"category": d['category'], "title": d['title'], "risk_rank": d['risk_rank']}
                for d in batch
            ]

            embeddings = self._embed.generate_batch(texts)
            if embeddings is None:
                print(f"Fallo en lote {start // batch_size + 1}. Abortando.")
                return

            try:
                self._vector_store.upsert(
                    settings.chroma_owasp_collection,
                    ids=ids, documents=texts,
                    embeddings=embeddings,
                    metadatas=metadatas,
                )
                print(f"   OK Lote {start // batch_size + 1} ({start + 1}-{end}/{total}) insertado.")
            except Exception as e:
                print(f"Error en lote {start // batch_size + 1}: {e}")
                return

        print(f"Indexacion completada. Total: {len(existing_ids) + total} documentos.")
