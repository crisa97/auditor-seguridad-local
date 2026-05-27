#!/usr/bin/env python3
"""
Migrador del cache local NVD (nvd_full_cache.json) a MongoDB + ChromaDB.

Uso:
    python migrar_nvd_cache.py
    python migrar_nvd_cache.py --cache-path ruta/al/nvd_full_cache.json
    python migrar_nvd_cache.py --batch-size 100 --force
"""
import argparse
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from src.domain.models import Cve
from src.infrastructure.config import settings
from src.infrastructure.di import get_cve_repository, get_embedding_service, get_vector_store
from src.adapters.mongodb.connection import MongoConnection

logger = logging.getLogger("nvd_cache_migration")


def _setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _load_cache(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.info("Cache cargado: %d entradas desde %s", len(data), path)
    return data


def _deduplicate(entries: list[dict]) -> list[dict]:
    cve_repo = get_cve_repository()
    existing_ids = set(cve_repo.get_all_ids())
    logger.info("CVEs existentes en MongoDB: %d", len(existing_ids))

    new_entries = [e for e in entries if e["id"] not in existing_ids]
    logger.info("CVEs nuevas a migrar: %d (de %d totales)", len(new_entries), len(entries))
    return new_entries


def _migrate(entries: list[dict], batch_size: int) -> None:
    cve_repo = get_cve_repository()
    embed_service = get_embedding_service()
    vector_store = get_vector_store()

    chroma_collection = settings.chroma_nvd_collection
    chroma_existing = set(vector_store.get_existing_ids(chroma_collection))
    chroma_lock = Lock()

    def _build_batch(start: int, end: int) -> tuple:
        batch = entries[start:end]
        docs = []
        ids = []
        for entry in batch:
            doc = (
                f"CVE ID: {entry['id']}\n"
                f"Severidad: {entry['severity']} (CVSS: {entry['score']})\n"
                f"Descripcion: {entry['description']}"
            )
            docs.append(doc)
            ids.append(entry["id"])

        cve_models = [
            Cve(id=e["id"], description=e["description"], severity=e["severity"], score=e["score"])
            for e in batch
        ]
        cve_repo.store_bulk(cve_models)

        with chroma_lock:
            new_ids_local = [eid for eid in ids if eid not in chroma_existing]
        new_docs = [docs[i] for i, eid in enumerate(ids) if eid in new_ids_local]

        if not new_ids_local:
            return start, end, 0, 0, 0, 0

        embeddings = embed_service.generate_batch(new_docs)
        if embeddings is None:
            raise RuntimeError(f"Fallo embedding lote {start // batch_size + 1}")

        chroma_start = time.time()
        vector_store.upsert(
            chroma_collection,
            ids=new_ids_local,
            documents=new_docs,
            embeddings=embeddings,
        )
        chroma_elapsed = time.time() - chroma_start

        with chroma_lock:
            chroma_existing.update(new_ids_local)

        return start, end, len(batch), len(new_ids_local), 0, chroma_elapsed

    total = len(entries)
    inserted_mongo = 0
    inserted_chroma = 0

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}
        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            future = pool.submit(_build_batch, start, end)
            futures[future] = (start, end)

        for future in as_completed(futures):
            start, end, mongo_count, chroma_count, _, chroma_elapsed = future.result()
            inserted_mongo += mongo_count
            inserted_chroma += chroma_count
            logger.info(
                "Lote %d-%d/%d: Chroma=%.1fs (%d nuevas)",
                start + 1, end, total,
                chroma_elapsed, chroma_count,
            )

    logger.info("Migracion completada: %d CVEs en MongoDB, %d en ChromaDB", inserted_mongo, inserted_chroma)


def main():
    _setup_logging()

    parser = argparse.ArgumentParser(description="Migrar cache NVD local a MongoDB + ChromaDB")
    parser.add_argument(
        "--cache-path",
        default="nvd_full_cache.json",
        help="Ruta al archivo nvd_full_cache.json (default: nvd_full_cache.json)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=settings.nvd_batch_size,
        help=f"Tamano de lote para embeddings (default: {settings.nvd_batch_size})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Migrar incluso si el CVE ya existe (reemplaza en ChromaDB)",
    )
    args = parser.parse_args()

    logger.info("Conectando a MongoDB...")
    if not MongoConnection.ping():
        logger.error("No se pudo conectar a MongoDB.")
        sys.exit(1)
    logger.info("MongoDB conectado.")

    entries = _load_cache(args.cache_path)

    if not args.force:
        entries = _deduplicate(entries)
        if not entries:
            logger.info("No hay CVEs nuevas para migrar.")
            return
    else:
        logger.info("Modo --force: migrando todas las %d entradas", len(entries))

    _migrate(entries, args.batch_size)


if __name__ == "__main__":
    main()
