import datetime
import os
import subprocess
import sys
from typing import Optional

import requests

from src.domain.models import Cve, Exploit
from src.ports.repositories import ICveRepository, IExploitRepository
from src.ports.services import IEmbeddingService, IVectorStore
from src.infrastructure.config import settings


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
        except Exception:
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
                try:
                    for cve_id in batch_ids:
                        self._cve_repo.store(Cve(id=cve_id, description="", chroma_id=cve_id))
                except Exception:
                    pass
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
        all_cves: list[dict] = []
        while True:
            try:
                resp = requests.get(
                    settings.nvd_api_base_url,
                    params=params,
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
                import time
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

    def _parse_files(self) -> list[dict]:
        exploits_dir = os.path.join(settings.exploitdb_local_dir, "exploits")
        if not os.path.isdir(exploits_dir):
            print(f"No se encontro la carpeta {exploits_dir}")
            sys.exit(1)

        documents: list[dict] = []
        for root, dirs, files in os.walk(exploits_dir):
            for file in files:
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
                except Exception:
                    pass
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

        total = len(new_docs)
        for start in range(0, total, settings.exploit_batch_size):
            end = min(start + settings.exploit_batch_size, total)
            batch = new_docs[start:end]
            texts = [d['text'] for d in batch]
            ids = [d['id'] for d in batch]
            paths = [d['path'] for d in batch]

            print(f"Lote {start // settings.exploit_batch_size + 1}: generando embeddings...")
            embeddings = self._embed.generate_batch(texts)
            if embeddings is None:
                print(f"Fallo en lote. Abortando.")
                return

            self._vector_store.upsert(
                settings.chroma_exploit_collection,
                ids=ids,
                documents=texts,
                embeddings=embeddings,
                metadatas=[{"path": p} for p in paths],
            )

            try:
                for exp_id in ids:
                    self._exploit_repo.store(Exploit(id=exp_id, path="", text="", chroma_id=exp_id))
            except Exception:
                pass

            print(f"   OK Lote {start // settings.exploit_batch_size + 1} ({start + 1}-{end}/{total}) insertado.")

        print(f"Indexacion completada. Total: {len(existing_ids) + total} exploits.")
