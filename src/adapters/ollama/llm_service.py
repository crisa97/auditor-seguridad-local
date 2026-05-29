import logging
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
        "\u2022 Severidad: Alta\n"
        "\u2022 Ubicacion: archivo.php:10\n"
        "\u2022 Descripcion: texto\n"
        "\u2022 Mitigacion: texto\n"
        "\u2022 CVE o CWE: CWE-89\n"
        "\u2022 OWASP: A1 Injection"
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
        try:
            r = requests.post(
                f"{settings.ollama_api_url}/chat",
                json=payload,
                timeout=timeout,
            )
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "")
        except requests.Timeout:
            logger.error("Timeout al consultar Ollama (modelo=%s, timeout=%s)", model, timeout)
            return ""
        except requests.RequestException as e:
            logger.error("Error al consultar Ollama: %s", e)
            return ""
        except (KeyError, ValueError) as e:
            logger.error("Error al parsear respuesta de Ollama: %s", e)
            return ""
