import os

from src.infrastructure.config import settings
from src.infrastructure.di import get_analizador, get_analisis_repository
from src.tasks.celery_app import celery_app


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def analizar_proyecto(self, project_path: str, api_key: str = "", servicio_url: str = "") -> dict:
    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        raise FileNotFoundError(f"La ruta '{project_path}' no es un directorio valido.")

    analizador = get_analizador()
    try:
        result = analizador.execute(
            project_path=project_path,
            api_key=api_key,
            servicio_url=servicio_url,
        )
        return result
    except FileNotFoundError:
        raise
    except Exception as e:
        raise self.retry(exc=e)
