import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from generar_apikey import generar_api_key, almacenar_api_key
from src.adapters.postgresql.apikey_repository import hash_api_key
from src.adapters.postgresql.connection import PostgresConnection
from datetime import datetime, timedelta, timezone


def test_generar_api_key_longitud():
    key = generar_api_key()
    assert len(key) >= 32
    assert isinstance(key, str)


def test_generar_api_key_unica():
    keys = {generar_api_key() for _ in range(100)}
    assert len(keys) == 100


def test_generar_api_key_segura():
    key = generar_api_key()
    assert len(key) >= 32
    assert key.isprintable()


def test_hash_misma_key_mismo_salt():
    key = "super-secret-api-key-12345"
    h1 = hash_api_key(key, salt="test-salt")
    h2 = hash_api_key(key, salt="test-salt")
    assert h1 == h2


def test_hash_diferentes_keys():
    h1 = hash_api_key("key-a", salt="salt")
    h2 = hash_api_key("key-b", salt="salt")
    assert h1 != h2


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_api_key_valida(mock_get_conn):
    from validador import validar_api_key
    raw_key = "test-key-valida-123"
    key_hash = hash_api_key(raw_key, salt="test-salt")

    mock_cur = MagicMock()
    future = datetime.now(timezone.utc) + timedelta(days=30)
    mock_cur.fetchone.return_value = (key_hash, "test-", "Test Client", future, True, "rag:leer", None)

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    with patch("src.adapters.postgresql.apikey_repository.hash_api_key", return_value=key_hash):
        valida, msg, datos = validar_api_key(raw_key)

    assert valida
    assert "válida" in msg or "valida" in msg
    assert datos["nombre_cliente"] == "Test Client"


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_api_key_expirada(mock_get_conn):
    from validador import validar_api_key
    raw_key = "test-key-expirada"
    key_hash = hash_api_key(raw_key, salt="test-salt")

    mock_cur = MagicMock()
    past = datetime.now(timezone.utc) - timedelta(days=1)
    mock_cur.fetchone.return_value = (key_hash, "test-", "Expired Client", past, True, "rag:leer", None)

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    with patch("src.adapters.postgresql.apikey_repository.hash_api_key", return_value=key_hash):
        valida, msg, datos = validar_api_key(raw_key)

    assert not valida
    assert "expirada" in msg


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_api_key_desactivada(mock_get_conn):
    from validador import validar_api_key
    raw_key = "test-key-desactivada"
    key_hash = hash_api_key(raw_key, salt="test-salt")

    mock_cur = MagicMock()
    future = datetime.now(timezone.utc) + timedelta(days=30)
    mock_cur.fetchone.return_value = (key_hash, "test-", "Disabled Client", future, False, "rag:leer", None)

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    with patch("src.adapters.postgresql.apikey_repository.hash_api_key", return_value=key_hash):
        valida, msg, datos = validar_api_key(raw_key)

    assert not valida
    assert "desactivada" in msg


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_api_key_no_existe(mock_get_conn):
    from validador import validar_api_key
    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = None

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    valida, msg, datos = validar_api_key("key-no-existe")
    assert not valida
    assert "no encontrada" in msg
