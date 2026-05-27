import logging
from typing import Optional

from src.domain.models import Afirmacion
from src.ports.repositories import IConocimientoRepository
from src.adapters.postgresql.connection import PostgresConnection

logger = logging.getLogger(__name__)


class PostgresConocimientoRepository(IConocimientoRepository):
    def get_by_texto(self, texto: str) -> Optional[Afirmacion]:
        conn = PostgresConnection.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT texto_afirmacion, es_verdadero, fuente "
                "FROM conocimiento_validado WHERE texto_afirmacion = %s",
                (texto,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return Afirmacion(texto=row[0], es_verdadero=row[1], fuente=row[2] or "")
        finally:
            PostgresConnection.return_conn(conn)

    def registrar_pendiente(self, texto: str, consulta: str = "", modelo: str = "") -> bool:
        conn = PostgresConnection.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO pendiente_validacion "
                "(texto_afirmacion, consulta_original, modelo_respuesta) "
                "VALUES (%s, %s, %s)",
                (texto, consulta, modelo),
            )
            conn.commit()
            return True
        except Exception as e:
            logger.warning("Error registrando afirmacion pendiente: %s", e)
            return False
        finally:
            PostgresConnection.return_conn(conn)
