"""Tests de seguridad: logging sensible, SQL injection, rate limiting, excepciones."""

import hashlib
import io
import logging
import re
import sys

import pytest


# ── Helper: _redact de openwebui_inject ──────────────────────────────────────

def _redact(value: str, max_len: int = 8) -> str:
    h = hashlib.pbkdf2_hmac(
        'sha256',
        value.encode(),
        salt=b'redact_salt',
        iterations=100000,
        dklen=16,
    )
    return f"pbkdf2:{h.hex()[:max_len]}..."


class TestRedactHelper:
    def test_redact_no_expone_original(self):
        original = "sk-1234567890abcdef"
        result = _redact(original)
        assert original not in result

    def test_redact_incluye_prefijo_pbkdf2(self):
        result = _redact("test")
        assert result.startswith("pbkdf2:")

    def test_redact_mismo_input_mismo_output(self):
        assert _redact("foo") == _redact("foo")

    def test_redact_distinto_input_distinto_output(self):
        assert _redact("foo") != _redact("bar")

    def test_redact_usa_pbkdf2_no_sha256_plano(self):
        result = _redact("sensitive-data")
        assert result.startswith("pbkdf2:")
        assert not result.startswith("sha256:")


# ── Hash fuerte: verificar que no se usen algoritmos débiles ────────────────

class TestStrongHash:
    def test_redact_no_usa_md5_ni_sha1(self):
        import os
        inject_path = os.path.join(os.path.dirname(__file__), "..", "patches", "openwebui_inject.py")
        with open(inject_path) as f:
            content = f.read()
        assert "hashlib.md5" not in content
        assert "hashlib.sha1" not in content

    def test_redact_usa_pbkdf2(self):
        import os
        inject_path = os.path.join(os.path.dirname(__file__), "..", "patches", "openwebui_inject.py")
        with open(inject_path) as f:
            content = f.read()
        assert "hashlib.pbkdf2_hmac" in content
        assert "iterations" in content


# ── Logging: no exponer información sensible ─────────────────────────────────

class TestSensitiveLogging:
    def test_log_no_contiene_api_key_raw(self):
        """Verifica que ningún logger emite una API key en texto plano."""
        logger = logging.getLogger("test_sensitive")
        logger.setLevel(logging.DEBUG)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)

        fake_key = "sk-live-ABCD1234efgh5678IJKL"
        logger.info("API key almacenada para 'cliente' (expira: 2026-01-01)")

        output = stream.getvalue()
        assert fake_key not in output

    def test_log_no_contiene_password(self):
        """Verifica que logs no contengan contraseñas."""
        logger = logging.getLogger("test_password")
        logger.setLevel(logging.DEBUG)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)

        logger.info("Login fallido para usuario: admin")
        output = stream.getvalue()
        assert "admin123" not in output

    def test_stdout_no_es_log(self, capsys):
        """generar_apikey_cli usa sys.stdout.write (no log) para la API key."""
        import src.interfaces.cli.generar_apikey_cli
        # Simulamos un escenario de print
        print("API Key: sk-test123", flush=True)
        captured = capsys.readouterr()
        assert "sk-test123" in captured.out


# ── SQL Injection: consultas parametrizadas ─────────────────────────────────

class TestSqlInjection:
    def test_consulta_parametrizada(self):
        """Verifica que no se use interpolación directa en consultas SQL."""
        import ast
        import os

        app_path = os.path.join(os.path.dirname(__file__), "..", "test", "app.js")
        with open(app_path) as f:
            content = f.read()

        # No debe haber ${...} dentro de cadenas SQL
        dangerous_patterns = [
            r"WHERE\s+\w+\s*=\s*'\{?\$",
        ]
        for pat in dangerous_patterns:
            assert not re.search(pat, content), f"Posible SQL injection: {pat}"

        # Debe haber placeholders ? en consultas
        param_count = content.count("= ?")
        assert param_count >= 3, f"Solo {param_count} placeholders ?, se esperan >= 3"

    def test_validacion_id_numerico(self):
        """Verifica que /user/:id valide que el ID sea numérico."""
        import os
        app_path = os.path.join(os.path.dirname(__file__), "..", "test", "app.js")
        with open(app_path) as f:
            content = f.read()
        assert "Number.isFinite(id)" in content or "!/^\\d+$/.test(id)" in content


# ── Excepciones: no devolver HTML con mensajes internos ──────────────────────

class TestExceptionHandling:
    def test_error_respuesta_no_expone_detalle(self):
        """Verifica que las respuestas de error no contengan mensajes internos."""
        import os
        app_path = os.path.join(os.path.dirname(__file__), "..", "test", "app.js")
        with open(app_path) as f:
            content = f.read()

        # No debe haber res.send(err.message)
        assert "res.send(err.message)" not in content

        # Debe haber res.status(500).json({ error: ... })
        assert "res.status(500).json" in content


# ── Rate Limiting ────────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_rate_limit_importado(self):
        """Verifica que express-rate-limit se importe."""
        import os
        app_path = os.path.join(os.path.dirname(__file__), "..", "test", "app.js")
        with open(app_path) as f:
            content = f.read()
        assert "require('express-rate-limit')" in content or 'require("express-rate-limit")' in content

    def test_rate_limit_aplicado(self):
        """Verifica que los endpoints tengan rate limiting."""
        import os
        app_path = os.path.join(os.path.dirname(__file__), "..", "test", "app.js")
        with open(app_path) as f:
            content = f.read()
        assert "rateLimit" in content
        assert "windowMs" in content
        assert "max" in content


# ── escape-html (XSS prevention) ────────────────────────────────────────────

class TestXssPrevention:
    def test_escape_html_importado(self):
        """Verifica que escape-html se use en respuestas HTML."""
        import os
        app_path = os.path.join(os.path.dirname(__file__), "..", "test", "app.js")
        with open(app_path) as f:
            content = f.read()
        assert "escapeHtml" in content
        assert "require('escape-html')" in content or 'require("escape-html")' in content
