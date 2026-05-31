import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from src.adapters.postgresql.apikey_repository import hash_api_key, PostgresApiKeyRepository
from src.adapters.postgresql.connection import PostgresConnection
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


class ApiKeyItem(BaseModel):
    id: int
    key_prefix: str
    nombre_cliente: str
    fecha_creacion: str
    fecha_expiracion: str | None = None
    activa: bool
    permisos: str
    ultimo_uso: str | None = None
    usuario_id: int


class ToggleApiKeyRequest(BaseModel):
    activa: bool


def _row_to_apikey(row) -> ApiKeyItem:
    return ApiKeyItem(
        id=row[0],
        key_prefix=row[1],
        nombre_cliente=row[2],
        fecha_creacion=str(row[3]),
        fecha_expiracion=str(row[4]) if row[4] else None,
        activa=row[5],
        permisos=row[6],
        ultimo_uso=str(row[7]) if row[7] else None,
        usuario_id=row[8],
    )


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


@router.get("/apikeys", response_model=list[ApiKeyItem])
@require_auth(roles=["usuario", "admin"])
def list_api_keys(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    user = request.state.user
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        if user.get("rol") == "admin":
            cur.execute(
                "SELECT id, key_prefix, nombre_cliente, fecha_creacion, fecha_expiracion, activa, permisos, ultimo_uso, usuario_id FROM api_keys ORDER BY fecha_creacion DESC LIMIT %s OFFSET %s",
                (limit, offset),
            )
        else:
            cur.execute(
                "SELECT id, key_prefix, nombre_cliente, fecha_creacion, fecha_expiracion, activa, permisos, ultimo_uso, usuario_id FROM api_keys WHERE usuario_id = %s ORDER BY fecha_creacion DESC LIMIT %s OFFSET %s",
                (user.get("id", 0), limit, offset),
            )
        return [_row_to_apikey(row) for row in cur.fetchall()]
    except Exception as e:
        log.error("Error al listar API keys: %s", e)
        raise HTTPException(status_code=500, detail="Error al listar API keys")
    finally:
        PostgresConnection.return_conn(conn)


@router.put("/apikeys/{key_id}/toggle", response_model=dict)
@require_auth(roles=["usuario", "admin"])
def toggle_api_key(body: ToggleApiKeyRequest, request: Request, key_id: int):
    user = request.state.user
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        if user.get("rol") == "admin":
            cur.execute(
                "UPDATE api_keys SET activa = %s WHERE id = %s RETURNING id, key_prefix, nombre_cliente, fecha_creacion, fecha_expiracion, activa, permisos, ultimo_uso, usuario_id",
                (body.activa, key_id),
            )
        else:
            cur.execute(
                "UPDATE api_keys SET activa = %s WHERE id = %s AND usuario_id = %s RETURNING id, key_prefix, nombre_cliente, fecha_creacion, fecha_expiracion, activa, permisos, ultimo_uso, usuario_id",
                (body.activa, key_id, user.get("id", 0)),
            )
        row = cur.fetchone()
        conn.commit()
        if row is None:
            raise HTTPException(status_code=404, detail="API key no encontrada")
        api_key = _row_to_apikey(row)
        log.info("API key %s %s por usuario %s",
                 key_id, "activada" if body.activa else "desactivada", user.get("id"))
        return {"message": f"API key {'activada' if body.activa else 'desactivada'} exitosamente", "api_key": api_key.model_dump()}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al actualizar API key: %s", e)
        raise HTTPException(status_code=500, detail="Error al actualizar API key")
    finally:
        PostgresConnection.return_conn(conn)


@router.delete("/apikeys/{key_id}", response_model=dict)
@require_auth(roles=["usuario", "admin"])
def deactivate_api_key(request: Request, key_id: int):
    user = request.state.user
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        if user.get("rol") == "admin":
            cur.execute("UPDATE api_keys SET activa = FALSE WHERE id = %s RETURNING id", (key_id,))
        else:
            cur.execute(
                "UPDATE api_keys SET activa = FALSE WHERE id = %s AND usuario_id = %s RETURNING id",
                (key_id, user.get("id", 0)),
            )
        row = cur.fetchone()
        conn.commit()
        if row is None:
            raise HTTPException(status_code=404, detail="API key no encontrada")
        log.info("API key %s desactivada por usuario %s", key_id, user.get("id"))
        return {"message": "API key desactivada exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al desactivar API key: %s", e)
        raise HTTPException(status_code=500, detail="Error al desactivar API key")
    finally:
        PostgresConnection.return_conn(conn)
