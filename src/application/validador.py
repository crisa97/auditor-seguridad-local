from datetime import datetime, timezone
from typing import Optional

from src.domain.models import ApiKey, Afirmacion
from src.domain.enums import AccionValidacion
from src.domain.exceptions import (
    ApiKeyInvalidaError, ApiKeyExpiradaError, ApiKeyDesactivadaError,
    AfirmacionBloqueadaError,
)
from src.ports.repositories import IApiKeyRepository, IConocimientoRepository
from src.ports.services import IAfirmacionExtractor


class ResultadoValidacion:
    PERMITIR = AccionValidacion.PERMITIR
    BLOQUEAR = AccionValidacion.BLOQUEAR
    PENDIENTE = AccionValidacion.PENDIENTE

    def __init__(self, accion: str, afirmacion: str, mensaje: str = ""):
        self.accion = accion
        self.afirmacion = afirmacion
        self.mensaje = mensaje


class ValidarApiKey:
    def __init__(self, api_key_repo: IApiKeyRepository, hash_func=None):
        self._repo = api_key_repo
        self._hash_func = hash_func

    def execute(self, raw_key: str) -> tuple[bool, str, dict]:
        if self._hash_func:
            key_hash = self._hash_func(raw_key)
        else:
            from src.adapters.postgresql.apikey_repository import hash_api_key
            key_hash = hash_api_key(raw_key)

        api_key = self._repo.get_by_hash(key_hash)
        if api_key is None:
            return False, "API key no encontrada.", {}

        if not api_key.activa:
            return False, "API key desactivada.", {}

        if api_key.fecha_expiracion and datetime.now(timezone.utc) > api_key.fecha_expiracion.replace(tzinfo=timezone.utc):
            return False, "API key expirada.", {}

        self._repo.update_ultimo_uso(key_hash)

        return True, "API key valida.", {
            "nombre_cliente": api_key.nombre_cliente,
            "permisos": api_key.permisos,
        }


class ValidarAfirmacion:
    def __init__(
        self,
        conocimiento_repo: IConocimientoRepository,
        extractor: IAfirmacionExtractor,
    ):
        self._repo = conocimiento_repo
        self._extractor = extractor

    def validar_una(self, afirmacion: str) -> ResultadoValidacion:
        try:
            existente = self._repo.get_by_texto(afirmacion)
            if existente is None:
                return ResultadoValidacion(
                    ResultadoValidacion.PENDIENTE, afirmacion,
                    "Afirmacion no validada. Se registrara para revision.",
                )
            if not existente.es_verdadero:
                return ResultadoValidacion(
                    ResultadoValidacion.BLOQUEAR, afirmacion,
                    f"No puedo confirmar esa informacion, es un falso positivo conocido. "
                    f"(Fuente: {existente.fuente or 'desconocida'})",
                )
            return ResultadoValidacion(
                ResultadoValidacion.PERMITIR, afirmacion,
                "Afirmacion validada correctamente.",
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Error al validar afirmacion: %s", e)
            return ResultadoValidacion(
                ResultadoValidacion.PERMITIR, afirmacion,
                "Error de validacion, se permite la respuesta por seguridad.",
            )

    def validar_consulta(self, consulta: str) -> list[ResultadoValidacion]:
        afirmaciones = self._extractor.extract(consulta)
        if not afirmaciones:
            return []

        resultados = []
        for af in afirmaciones:
            res = self.validar_una(af)
            resultados.append(res)
            if res.accion == ResultadoValidacion.PENDIENTE:
                self._repo.registrar_pendiente(af, consulta)

        return resultados

    @staticmethod
    def hay_bloqueo(resultados: list[ResultadoValidacion]) -> bool:
        return any(r.accion == ResultadoValidacion.BLOQUEAR for r in resultados)
