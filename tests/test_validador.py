import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from validador import (
    extraer_afirmaciones, validar_afirmacion,
    validar_consulta, hay_bloqueo, hash_api_key,
)
from src.application.validador import ResultadoValidacion


def test_extraer_afirmaciones_detecta_declaraciones():
    texto = "El firewall es inseguro. Los sistemas Linux son vulnerables."
    resultados = extraer_afirmaciones(texto)
    assert len(resultados) >= 1
    assert any("firewall" in r for r in resultados)


def test_extraer_afirmaciones_sin_afirmaciones():
    texto = "Hola, ¿cómo estás?"
    resultados = extraer_afirmaciones(texto)
    assert resultados == []


def test_extraer_afirmaciones_ignora_fragmentos_cortos():
    texto = "El es alto."
    resultados = extraer_afirmaciones(texto)
    assert all(len(r) > 15 for r in resultados)


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_afirmacion_verdadera(mock_get_conn):
    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = ("el firewall es seguro", True, "fuente_confiable")
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    resultado = validar_afirmacion("el firewall es seguro")
    assert resultado.accion == ResultadoValidacion.PERMITIR
    assert "validada" in resultado.mensaje


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_afirmacion_falsa(mock_get_conn):
    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = ("el firewall es inseguro", False, "nist_report")
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    resultado = validar_afirmacion("el firewall es inseguro")
    assert resultado.accion == ResultadoValidacion.BLOQUEAR
    assert "falso positivo" in resultado.mensaje


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_afirmacion_no_existe(mock_get_conn):
    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = None
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    resultado = validar_afirmacion("afirmación nueva desconocida")
    assert resultado.accion == ResultadoValidacion.PENDIENTE
    assert "validada" in resultado.mensaje.lower()


@patch("src.adapters.postgresql.connection.PostgresConnection.get_conn")
def test_validar_consulta_con_bloqueo(mock_get_conn):
    mock_cur = MagicMock()
    mock_cur.fetchone.side_effect = [
        ("El firewall es inseguro", False, "nist"),
        ("los sistemas Linux son vulnerables", False, "nist"),
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_get_conn.return_value = mock_conn

    consulta = "El firewall es inseguro y los sistemas Linux son vulnerables."
    resultados = validar_consulta(consulta)
    assert len(resultados) >= 1
    assert hay_bloqueo(resultados)


def test_hash_api_key_consistente():
    h1 = hash_api_key("test-key-123", salt="test-salt")
    h2 = hash_api_key("test-key-123", salt="test-salt")
    assert h1 == h2
    assert len(h1) == 64


def test_hash_api_key_diferente_salt():
    h1 = hash_api_key("test-key", salt="salt-a")
    h2 = hash_api_key("test-key", salt="salt-b")
    assert h1 != h2


def test_hash_api_key_diferente_key():
    h1 = hash_api_key("key-1", salt="salt")
    h2 = hash_api_key("key-2", salt="salt")
    assert h1 != h2
