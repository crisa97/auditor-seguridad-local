import logging
from typing import Optional

import chromadb
import chromadb.errors

from src.ports.services import IVectorStore
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


class ChromaVectorStore(IVectorStore):
    def __init__(self):
        self._client = chromadb.HttpClient(
            host=settings.chroma_host,
            port=int(settings.chroma_port),
        )

    def _get_collection(self, name: str):
        try:
            return self._client.get_collection(name=name)
        except (chromadb.errors.NotFoundError, ValueError):
            return self._client.create_collection(name=name)

    def query(self, embedding: list[float], collection_name: str, n_results: int = 3) -> list[str]:
        try:
            collection = self._get_collection(collection_name)
            results = collection.query(
                query_embeddings=[embedding],
                n_results=n_results,
            )
            return results['documents'][0] if results['documents'] else []
        except Exception as e:
            logger.error("Error querying ChromaDB collection '%s': %s", collection_name, e)
            return []

    def get_existing_ids(self, collection_name: str) -> set[str]:
        try:
            collection = self._get_collection(collection_name)
            existing_ids: set[str] = set()
            offset = 0
            while True:
                batch = collection.get(limit=settings.chroma_page_size, offset=offset, include=[])
                if not batch['ids']:
                    break
                existing_ids.update(batch['ids'])
                offset += len(batch['ids'])
            return existing_ids
        except Exception as e:
            logger.error("Error getting existing IDs from ChromaDB '%s': %s", collection_name, e)
            return set()

    def upsert(self, collection_name: str, ids: list[str], documents: list[str],
               embeddings: list[list[float]], metadatas: Optional[list[dict]] = None) -> None:
        try:
            collection = self._get_collection(collection_name)
            kwargs = {"ids": ids, "documents": documents, "embeddings": embeddings}
            if metadatas is not None:
                kwargs["metadatas"] = metadatas
            collection.upsert(**kwargs)
        except Exception as e:
            logger.error("Error upserting to ChromaDB collection '%s': %s", collection_name, e)
            raise
