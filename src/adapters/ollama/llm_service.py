from typing import Optional

import requests

from src.ports.services import ILlmService
from src.infrastructure.config import settings


class OllamaLlmService(ILlmService):
    def generate(self, prompt: str, model: str | None = None, **options) -> str:
        model = model or settings.analyzer_model
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_ctx": options.get("num_ctx", settings.llm_num_ctx),
                "num_predict": options.get("num_predict", settings.llm_num_predict),
                "temperature": options.get("temperature", settings.llm_temperature),
            },
        }
        timeout = options.get("timeout", settings.ollama_timeout)
        r = requests.post(
            f"{settings.ollama_api_url}/generate",
            json=payload,
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json().get("response", "")
