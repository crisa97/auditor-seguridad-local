from functools import wraps

from fastapi import HTTPException, Request

from src.interfaces.dashboard.auth import decode_token


def require_auth(roles: list[str] | None = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            if request is None:
                raise HTTPException(status_code=500, detail="Request context not found")

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="Token no proporcionado")

            token = auth_header[7:]
            payload = decode_token(token)

            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Tipo de token invalido")

            user_rol = payload.get("rol", "")
            if roles and user_rol not in roles:
                raise HTTPException(status_code=403, detail="Permiso insuficiente")

            request.state.user = {
                "id": int(payload["sub"]),
                "rol": user_rol,
            }
            return func(*args, **kwargs)
        return wrapper
    return decorator
