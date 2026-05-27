import logging
import time
from typing import Optional

import requests

from src.ports.services import IEmbeddingService
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


class OllamaEmbeddingService(IEmbeddingService):
    def generate(self, text: str) -> Optional[list[float]]:
        payload = {"model": settings.embedding_model, "input": [text]}
        try:
            r = requests.post(
                f"{settings.ollama_api_url}/embed",
                json=payload,
                timeout=settings.embed_single_timeout,
            )
            r.raise_for_status()
            return r.json()["embeddings"][0]
        except Exception as e:
            logger.warning("Error generating single embedding: %s", e)
            return None

    def generate_batch(self, texts: list[str]) -> Optional[list[list[float]]]:
        payload = {"model": settings.embedding_model, "input": texts}
        for attempt in range(settings.embed_max_retries):
            try:
                r = requests.post(
                    f"{settings.ollama_api_url}/embed",
                    json=payload,
                    timeout=settings.embed_batch_timeout,
                )
                r.raise_for_status()
                data = r.json()
                if "embeddings" in data:
                    return data["embeddings"]
            except requests.Timeout:
                if attempt < settings.embed_max_retries - 1:
                    time.sleep(5)
                    continue
            except Exception as e:
                logger.warning("Error generating batch embeddings: %s", e)
                break
        return None
