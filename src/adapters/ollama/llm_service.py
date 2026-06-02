import logging
import time
from typing import Optional

import requests

from src.ports.services import ILlmService
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


class OllamaLlmService(ILlmService):
    SYSTEM_PROMPT = (
        "Responde en espanol. Cada vulnerabilidad empieza con su nombre (sin prefijos). "
        "Ejemplo:\n"
        "SQL Injection\n"
        "•  Severidad: Alta\n"
        "•  Ubicacion: archivo.php:10\n"
        "•  Descripcion: texto\n"
        "•  Mitigacion: texto\n"
        "•  CVE o CWE: CWE-89\n"
        "•  OWASP: A1 Injection"
    )

    def generate(self, prompt: str, model: str | None = None, **options) -> str:
        model = model or settings.analyzer_model
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "keep_alive": "30m",
            "options": {
                "num_ctx": options.get("num_ctx", settings.llm_num_ctx),
                "num_predict": options.get("num_predict", settings.llm_num_predict),
                "temperature": options.get("temperature", settings.llm_temperature),
            },
        }
        timeout = options.get("timeout", settings.ollama_timeout)
        last_error = None

        for attempt in range(2):
            try:
                r = requests.post(
                    f"{settings.ollama_api_url}/chat",
                    json=payload,
                    timeout=timeout,
                )
                r.raise_for_status()
                return r.json().get("message", {}).get("content", "")
            except requests.Timeout:
                last_error = f"Timeout al consultar Ollama (modelo={model}, timeout={timeout})"
                logger.warning("%s (intento %d/2)", last_error, attempt + 1)
                if attempt == 0:
                    time.sleep(5)
                    continue
            except requests.RequestException as e:
                logger.error("Error al consultar Ollama: %s", e)
                return ""
            except (KeyError, ValueError) as e:
                logger.error("Error al parsear respuesta de Ollama: %s", e)
                return ""

        logger.error(last_error)
        return ""
