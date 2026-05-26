from enum import Enum


class EstadoAnalisis(str, Enum):
    PENDIENTE = "pendiente"
    EN_PROCESO = "en_proceso"
    COMPLETADO = "completado"
    FALLIDO = "fallido"


class AccionValidacion(str, Enum):
    PERMITIR = "permitir"
    BLOQUEAR = "bloquear"
    PENDIENTE = "pendiente"
