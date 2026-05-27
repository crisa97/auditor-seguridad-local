"""
Wrapper backward-compatible.
"""
from datetime import datetime, timezone

from src.infrastructure.config import settings
from src.adapters.postgresql.apikey_repository import hash_api_key as _hash_api_key, PostgresApiKeyRepository

# Re-export para backward compatibility
hash_api_key = _hash_api_key
from src.adapters.postgresql.conocimiento_repository import PostgresConocimientoRepository
from src.adapters.afirmaciones.extractor import RegexAfirmacionExtractor
from src.application.validador import ValidarApiKey, ValidarAfirmacion, ResultadoValidacion

# ── Conexion a BD ──
def _get_conn():
    from src.adapters.postgresql.connection import PostgresConnection
    return PostgresConnection.get_conn()

# ── Extraccion de afirmaciones ──
_AFIRMACION_PATTERNS = RegexAfirmacionExtractor._PATTERNS

def extraer_afirmaciones(texto: str) -> list[str]:
    return RegexAfirmacionExtractor().extract(texto)

# ── Validacion ──
def validar_afirmacion(afirmacion: str) -> ResultadoValidacion:
    repo = PostgresConocimientoRepository()
    extractor = RegexAfirmacionExtractor()
    validador = ValidarAfirmacion(repo, extractor)
    return validador.validar_una(afirmacion)

def registrar_pendiente(afirmacion: str, consulta_original: str = "",
                         modelo_respuesta: str = "") -> bool:
    repo = PostgresConocimientoRepository()
    return repo.registrar_pendiente(afirmacion, consulta_original, modelo_respuesta)

def validar_consulta(consulta: str) -> list[ResultadoValidacion]:
    repo = PostgresConocimientoRepository()
    extractor = RegexAfirmacionExtractor()
    validador = ValidarAfirmacion(repo, extractor)
    return validador.validar_consulta(consulta)

def hay_bloqueo(resultados: list[ResultadoValidacion]) -> bool:
    return ValidarAfirmacion.hay_bloqueo(resultados)

# ── API key validation ──
def validar_api_key(raw_key: str) -> tuple[bool, str, dict]:
    repo = PostgresApiKeyRepository()
    validador = ValidarApiKey(repo)
    return validador.execute(raw_key)
