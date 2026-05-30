import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.adapters.postgresql.apikey_repository import hash_api_key, PostgresApiKeyRepository
from src.domain.models import ApiKey
from src.interfaces.dashboard.middleware import require_auth

log = logging.getLogger("dashboard.routers.apikeys")
router = APIRouter()


class CreateApiKeyRequest(BaseModel):
    nombre_cliente: str = Field(..., min_length=1, max_length=255)
    permisos: str = Field(default="rag:leer", max_length=100)
    dias_validez: int = Field(default=365, ge=1, le=3650)


class CreateApiKeyResponse(BaseModel):
    api_key: str
    key_prefix: str
    nombre_cliente: str
    permisos: str
    fecha_expiracion: str
    advertencia: str = "Guarda esta clave, no se mostrara de nuevo."


@router.post("/apikeys", response_model=CreateApiKeyResponse)
@require_auth(roles=["usuario", "admin"])
def create_api_key(body: CreateApiKeyRequest, request: Request):
    import secrets
    raw_key = secrets.token_urlsafe(32)
    key_hash = hash_api_key(raw_key)
    key_prefix = raw_key[:8]
    expiracion = datetime.now(timezone.utc) + timedelta(days=body.dias_validez)

    try:
        repo = PostgresApiKeyRepository()
        repo.store(ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            nombre_cliente=body.nombre_cliente,
            permisos=body.permisos,
            fecha_expiracion=expiracion,
            usuario_id=request.state.user.get("id", 0),
        ))
        log.info("API key creada para '%s' por usuario %s",
                 body.nombre_cliente, request.state.user.get("id"))
        return CreateApiKeyResponse(
            api_key=raw_key,
            key_prefix=key_prefix,
            nombre_cliente=body.nombre_cliente,
            permisos=body.permisos,
            fecha_expiracion=expiracion.isoformat(),
        )
    except Exception as e:
        log.error("Error al almacenar API key: %s", e)
        raise HTTPException(status_code=500, detail="Error al crear API key")
