#! /usr/bin/env python3
"""
seed_admin.py — Crea el primer usuario administrador en PostgreSQL.

Uso:
  python3 seed_admin.py --email admin@seguridad.local --password "contraseña_segura" --nombre "Admin"
"""

import argparse
import logging
import sys

from src.adapters.postgresql.connection import PostgresConnection

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("seed_admin")


def seed_admin(email: str, password: str, nombre: str):
    import bcrypt

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    conn = PostgresConnection.get_conn()
    try:
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone() is not None:
            log.warning("El usuario '%s' ya existe. Omitiendo.", email)
            return True

        cur.execute(
            "INSERT INTO users (email, password_hash, nombre, rol) VALUES (%s, %s, %s, 'admin')",
            (email, password_hash, nombre),
        )
        conn.commit()
        log.info("Usuario administrador creado exitosamente:")
        log.info("  Email: %s", email)
        log.info("  Nombre: %s", nombre)
        log.info("  Rol: admin")
        return True
    except Exception as e:
        log.error("Error al crear usuario admin: %s", e)
        return False
    finally:
        PostgresConnection.return_conn(conn)


def main():
    parser = argparse.ArgumentParser(description="Crea el primer usuario administrador")
    parser.add_argument("--email", required=True, help="Email del administrador")
    parser.add_argument("--password", required=True, help="Contraseña del administrador")
    parser.add_argument("--nombre", required=True, help="Nombre del administrador")
    args = parser.parse_args()

    success = seed_admin(args.email, args.password, args.nombre)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
