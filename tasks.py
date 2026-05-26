"""
Wrapper backward-compatible.
"""
from src.tasks.celery_app import celery_app as app
from src.tasks.analysis_tasks import analizar_proyecto
