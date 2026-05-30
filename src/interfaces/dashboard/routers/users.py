import logging
from typing import Optional

import bcrypt
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from src.adapters.postgresql.connection import PostgresConnection
from src.interfaces.dashboard.middleware import require_auth

log = logging.getLogger("dashboard.routers.users")
router = APIRouter()


class UserItem(BaseModel):
    id: int
    email: str
    nombre: str
    rol: str
    activo: bool
    creado_en: str
    ultimo_login: Optional[str] = None


class UserCreateRequest(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    nombre: str = Field(..., min_length=1, max_length=255)
    rol: str = Field(default="usuario", pattern="^(admin|usuario)$")


class UserUpdateRequest(BaseModel):
    email: Optional[str] = Field(None, max_length=255)
    nombre: Optional[str] = Field(None, min_length=1, max_length=255)
    rol: Optional[str] = Field(None, pattern="^(admin|usuario)$")
    activo: Optional[bool] = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


class UpdateProfileRequest(BaseModel):
    nombre: Optional[str] = Field(None, min_length=1, max_length=255)
    email: Optional[str] = Field(None, max_length=255)


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def _row_to_user(row) -> UserItem:
    return UserItem(
        id=row[0],
        email=row[1],
        nombre=row[2],
        rol=row[3],
        activo=row[4],
        creado_en=str(row[5]),
        ultimo_login=str(row[6]) if row[6] else None,
    )


@router.get("/users", response_model=list[UserItem])
@require_auth(roles=["admin"])
def list_users(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    rol: Optional[str] = Query(default=None),
):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        query = "SELECT id, email, nombre, rol, activo, creado_en, ultimo_login FROM users"
        params = []
        conditions = []
        if rol:
            conditions.append("rol = %s")
            params.append(rol)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cur.execute(query, params)
        return [_row_to_user(row) for row in cur.fetchall()]
    except Exception as e:
        log.error("Error al listar usuarios: %s", e)
        raise HTTPException(status_code=500, detail="Error al listar usuarios")
    finally:
        PostgresConnection.return_conn(conn)


@router.get("/users/me", response_model=UserItem)
@require_auth(roles=["admin", "usuario"])
def get_profile(request: Request):
    user_id = request.state.user.get("id")
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, nombre, rol, activo, creado_en, ultimo_login FROM users WHERE id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return _row_to_user(row)
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al obtener perfil: %s", e)
        raise HTTPException(status_code=500, detail="Error al obtener perfil")
    finally:
        PostgresConnection.return_conn(conn)


@router.get("/users/{user_id}", response_model=UserItem)
@require_auth(roles=["admin"])
def get_user(request: Request, user_id: int):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, nombre, rol, activo, creado_en, ultimo_login FROM users WHERE id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return _row_to_user(row)
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al obtener usuario: %s", e)
        raise HTTPException(status_code=500, detail="Error al obtener usuario")
    finally:
        PostgresConnection.return_conn(conn)


@router.post("/users", response_model=dict)
@require_auth(roles=["admin"])
def create_user(body: UserCreateRequest, request: Request):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (body.email,))
        if cur.fetchone() is not None:
            raise HTTPException(status_code=409, detail="El email ya esta registrado")

        password_hash = _hash_password(body.password)
        cur.execute(
            "INSERT INTO users (email, password_hash, nombre, rol) VALUES (%s, %s, %s, %s) RETURNING id, email, nombre, rol, activo, creado_en, ultimo_login",
            (body.email, password_hash, body.nombre, body.rol),
        )
        row = cur.fetchone()
        conn.commit()
        user = _row_to_user(row)
        log.info("Usuario creado: %s (rol=%s) por admin %s",
                 body.email, body.rol, request.state.user.get("id"))
        return {"message": "Usuario creado exitosamente", "user": user.model_dump()}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al crear usuario: %s", e)
        raise HTTPException(status_code=500, detail="Error al crear usuario")
    finally:
        PostgresConnection.return_conn(conn)


@router.put("/users/me", response_model=UserItem)
@require_auth(roles=["admin", "usuario"])
def update_profile(body: UpdateProfileRequest, request: Request):
    user_id = request.state.user.get("id")
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        updates = []
        params = []
        if body.nombre is not None:
            updates.append("nombre = %s")
            params.append(body.nombre)
        if body.email is not None:
            cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (body.email, user_id))
            if cur.fetchone() is not None:
                raise HTTPException(status_code=409, detail="El email ya esta en uso")
            updates.append("email = %s")
            params.append(body.email)
        if not updates:
            raise HTTPException(status_code=400, detail="Sin cambios para actualizar")
        params.append(user_id)
        cur.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = %s RETURNING id, email, nombre, rol, activo, creado_en, ultimo_login",
            params,
        )
        row = cur.fetchone()
        conn.commit()
        if row is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return _row_to_user(row)
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al actualizar perfil: %s", e)
        raise HTTPException(status_code=500, detail="Error al actualizar perfil")
    finally:
        PostgresConnection.return_conn(conn)


@router.put("/users/{user_id}", response_model=dict)
@require_auth(roles=["admin"])
def update_user(body: UserUpdateRequest, request: Request, user_id: int):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        updates = []
        params = []
        if body.email is not None:
            cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (body.email, user_id))
            if cur.fetchone() is not None:
                raise HTTPException(status_code=409, detail="El email ya esta en uso")
            updates.append("email = %s")
            params.append(body.email)
        if body.nombre is not None:
            updates.append("nombre = %s")
            params.append(body.nombre)
        if body.rol is not None:
            updates.append("rol = %s")
            params.append(body.rol)
        if body.activo is not None:
            updates.append("activo = %s")
            params.append(body.activo)
        if not updates:
            raise HTTPException(status_code=400, detail="Sin cambios para actualizar")
        params.append(user_id)
        cur.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = %s RETURNING id, email, nombre, rol, activo, creado_en, ultimo_login",
            params,
        )
        row = cur.fetchone()
        conn.commit()
        if row is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user = _row_to_user(row)
        log.info("Usuario %s actualizado por admin %s", user_id, request.state.user.get("id"))
        return {"message": "Usuario actualizado exitosamente", "user": user.model_dump()}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al actualizar usuario: %s", e)
        raise HTTPException(status_code=500, detail="Error al actualizar usuario")
    finally:
        PostgresConnection.return_conn(conn)


@router.delete("/users/{user_id}", response_model=dict)
@require_auth(roles=["admin"])
def deactivate_user(request: Request, user_id: int):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET activo = FALSE WHERE id = %s RETURNING id", (user_id,))
        row = cur.fetchone()
        conn.commit()
        if row is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        log.info("Usuario %s desactivado por admin %s", user_id, request.state.user.get("id"))
        return {"message": "Usuario desactivado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al desactivar usuario: %s", e)
        raise HTTPException(status_code=500, detail="Error al desactivar usuario")
    finally:
        PostgresConnection.return_conn(conn)


@router.post("/users/{user_id}/reset-password", response_model=dict)
@require_auth(roles=["admin"])
def reset_password(body: ResetPasswordRequest, request: Request, user_id: int):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        password_hash = _hash_password(body.new_password)
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s RETURNING id", (password_hash, user_id))
        row = cur.fetchone()
        conn.commit()
        if row is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        log.info("Password reset para usuario %s por admin %s", user_id, request.state.user.get("id"))
        return {"message": "Contraseña restablecida exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al restablecer password: %s", e)
        raise HTTPException(status_code=500, detail="Error al restablecer contraseña")
    finally:
        PostgresConnection.return_conn(conn)


@router.post("/users/me/change-password", response_model=dict)
@require_auth(roles=["admin", "usuario"])
def change_password(body: ChangePasswordRequest, request: Request):
    user_id = request.state.user.get("id")
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        if not _verify_password(body.current_password, row[0]):
            raise HTTPException(status_code=401, detail="Contraseña actual incorrecta")
        password_hash = _hash_password(body.new_password)
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, user_id))
        conn.commit()
        return {"message": "Contraseña cambiada exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        log.error("Error al cambiar password: %s", e)
        raise HTTPException(status_code=500, detail="Error al cambiar contraseña")
    finally:
        PostgresConnection.return_conn(conn)
