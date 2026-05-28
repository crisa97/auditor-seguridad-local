import logging
import time
from typing import Optional

import requests

from src.ports.services import IEmbeddingService
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


class OllamaEmbeddingService(IEmbeddingService):
    def generate(self, text: str) -> Optional[list[float]]:
        result = self.generate_batch([text])
        if result:
            return result[0]
        return None

    @staticmethod
    def _is_binary(t: str) -> bool:
        if not t:
            return True
        suspicious = sum(
            1 for c in t
            if c < " " and c not in "\n\r\t"
            or c == "\ufffd"
            or c in "\u0000\u0080\u009f\u00ad"
        )
        return suspicious / len(t) > 0.05

    def _clean_text(self, t: str) -> str:
        t = t.replace("\x00", "")
        t = "".join(c if c >= " " or c in "\n\r\t" else " " for c in t)
        t = t[:4000].strip()
        if self._is_binary(t):
            return ""
        return t

    def _is_context_error(self, e: Exception) -> bool:
        """Detecta si el error es por exceder el contexto de tokens."""
        if hasattr(e, "response") and e.response is not None:
            try:
                body = e.response.text
                return "input length exceeds the context length" in body
            except Exception:
                pass
        return False

    def generate_batch(self, texts: list[str]) -> Optional[list[list[float]]]:
        cleaned = [self._clean_text(t) for t in texts]
        cleaned = [t for t in cleaned if t]
        if not cleaned:
            logger.warning("All texts in batch were empty after cleaning")
            return None

        # Si es un solo texto, truncar progresivamente hasta que quepa
        if len(cleaned) == 1:
            return self._generate_single_with_retry(cleaned[0])

        payload = {"model": settings.embedding_model, "input": cleaned}
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
                detail = ""
                if hasattr(e, "response") and e.response is not None:
                    try:
                        detail = e.response.text[:500]
                    except Exception:
                        pass
                # Si es error de contexto, hacer binary split del batch
                if self._is_context_error(e):
                    logger.warning("Contexto excedido en batch de %d textos — dividiendo...", len(cleaned))
                    mid = len(cleaned) // 2
                    left = self.generate_batch(cleaned[:mid])
                    right = self.generate_batch(cleaned[mid:])
                    if left is None or right is None:
                        return None
                    return left + right
                logger.warning("Error generating batch embeddings (attempt %d/%d): %s | Response: %s",
                               attempt + 1, settings.embed_max_retries, e, detail)
                break
        return None

    def _generate_single_with_retry(self, text: str) -> Optional[list[list[float]]]:
        """Genera embedding para un solo texto, truncando si excede contexto."""
        for char_limit in [4000, 3000, 2000, 1000, 500]:
            t = text[:char_limit]
            if not t:
                break
            try:
                r = requests.post(
                    f"{settings.ollama_api_url}/embed",
                    json={"model": settings.embedding_model, "input": [t]},
                    timeout=settings.embed_single_timeout,
                )
                r.raise_for_status()
                return r.json()["embeddings"]
            except Exception as e:
                if self._is_context_error(e):
                    logger.warning("Texto aun muy largo con %d chars, truncando mas...", char_limit)
                    continue
                logger.warning("Error en embedding individual: %s", e)
                return None
        logger.error("No se pudo generar embedding incluso con 500 chars")
        return None
