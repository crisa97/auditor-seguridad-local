import logging
import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field

from src.adapters.postgresql.connection import PostgresConnection
from src.infrastructure.config import settings

log = logging.getLogger("dashboard.auth")
router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET") or settings.api_key_salt
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = 15
REFRESH_TOKEN_EXPIRE = 7


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


class RegisterRequest(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    nombre: str = Field(..., min_length=1, max_length=255)
    rol: str = Field(default="usuario", pattern="^(admin|usuario)$")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def _create_access_token(user_id: int, rol: str) -> str:
    payload = {
        "sub": str(user_id),
        "rol": rol,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _create_refresh_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalido")


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password_hash, nombre, rol FROM users WHERE email = %s AND activo = TRUE",
            (body.email,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Credenciales invalidas")

        user_id, email, password_hash, nombre, rol = row

        if not _verify_password(body.password, password_hash):
            raise HTTPException(status_code=401, detail="Credenciales invalidas")

        cur.execute(
            "UPDATE users SET ultimo_login = NOW() WHERE id = %s",
            (user_id,),
        )
        conn.commit()

        access_token = _create_access_token(user_id, rol)
        refresh_token = _create_refresh_token(user_id)

        log.info("Login exitoso: %s (rol=%s)", email, rol)
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user={"id": user_id, "email": email, "nombre": nombre, "rol": rol},
        )
    finally:
        PostgresConnection.return_conn(conn)


@router.post("/register", response_model=dict)
def register(body: RegisterRequest):
    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (body.email,))
        if cur.fetchone() is not None:
            raise HTTPException(status_code=409, detail="El email ya esta registrado")

        password_hash = _hash_password(body.password)
        cur.execute(
            "INSERT INTO users (email, password_hash, nombre, rol) VALUES (%s, %s, %s, %s)",
            (body.email, password_hash, body.nombre, body.rol),
        )
        conn.commit()
        log.info("Usuario registrado: %s (rol=%s)", body.email, body.rol)
        return {"message": "Usuario registrado exitosamente", "email": body.email, "rol": body.rol}
    finally:
        PostgresConnection.return_conn(conn)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Tipo de token invalido")

    user_id = int(payload["sub"])

    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, nombre, rol FROM users WHERE id = %s AND activo = TRUE",
            (user_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")

        user_id, email, nombre, rol = row
        access_token = _create_access_token(user_id, rol)
        refresh_token = _create_refresh_token(user_id)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user={"id": user_id, "email": email, "nombre": nombre, "rol": rol},
        )
    finally:
        PostgresConnection.return_conn(conn)
