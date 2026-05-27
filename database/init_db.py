#!/usr/bin/env python3
"""
init_db.py — Inicializa las tablas en PostgreSQL.

Uso:
  python3 database/init_db.py                      # usa variables de entorno
  python3 database/init_db.py --db-url postgresql://...
"""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DB_URL

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def _load_schema() -> str:
    path = os.path.join(os.path.dirname(__file__), "schema.sql")
    if not os.path.exists(path):
        log.error("Schema file not found: %s", path)
        raise FileNotFoundError(f"Schema file not found: {path}")
    with open(path) as f:
        return f.read()


def init_db(db_url=None):
    if db_url is None:
        db_url = DB_URL
    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(_load_schema())
        cur.close()
        conn.close()
        log.info("Tablas creadas/verificadas correctamente.")
        return True
    except Exception as e:
        log.error("Error al inicializar la base de datos: %s", e)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inicializa tablas en PostgreSQL")
    parser.add_argument("--db-url", help="URL de conexion a PostgreSQL")
    args = parser.parse_args()
    success = init_db(args.db_url)
    exit(0 if success else 1)
