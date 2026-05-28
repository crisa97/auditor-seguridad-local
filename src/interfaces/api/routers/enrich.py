import logging
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.infrastructure.di import get_embedding_service, get_vector_store, get_validar_api_key
from src.infrastructure.config import settings

log = logging.getLogger("api.enrich")
router = APIRouter()

ENRICH_INTERNAL_TOKEN = os.getenv("ENRICH_INTERNAL_TOKEN", "")


class EnrichRequest(BaseModel):
    texto: str = Field(..., min_length=1, max_length=10000, description="Texto a enriquecer con contexto RAG")
    api_key: str = Field(..., min_length=1, description="API key de usuario o token interno")
    max_cves: int = Field(default=5, ge=0, le=20, description="Maximo de CVEs a incluir (0 = ninguna)")
    max_exploits: int = Field(default=5, ge=0, le=20, description="Maximo de exploits a incluir (0 = ninguno)")
    max_owasp: int = Field(default=3, ge=0, le=10, description="Maximo de docs OWASP Top 10 a incluir (0 = ninguno)")


class EnrichResponse(BaseModel):
    contexto: str = ""
    fuentes: list[dict] = []
    total_cves: int = 0
    total_exploits: int = 0
    total_owasp: int = 0


def _autorizar(body: EnrichRequest):
    """Valida que el request tenga autorizacion: token interno o API key valida con permiso rag:leer."""
    if ENRICH_INTERNAL_TOKEN and body.api_key == ENRICH_INTERNAL_TOKEN:
        return
    validador_key = get_validar_api_key()
    es_valida, msg, datos_cliente = validador_key.execute(body.api_key)
    if not es_valida:
        raise HTTPException(status_code=401, detail="API key invalida")
    permisos = (datos_cliente.get("permisos") or "").split(",")
    if "rag:leer" not in permisos and "rag:*" not in permisos:
        raise HTTPException(status_code=403, detail="Permiso insuficiente")


@router.post("/enrichir", response_model=EnrichResponse)
def enrichir(body: EnrichRequest):
    _autorizar(body)

    try:
        embed_service = get_embedding_service()
        vector_store = get_vector_store()
    except Exception as e:
        log.error("Error inicializando servicios RAG: %s", e)
        raise HTTPException(status_code=503, detail="Servicios RAG no disponibles")

    embeddings = embed_service.generate(body.texto)
    if embeddings is None:
        raise HTTPException(status_code=502, detail="Error generando embedding")

    cves_contexto: list[str] = []
    cves_fuentes: list[dict] = []
    exploits_contexto: list[str] = []
    exploits_fuentes: list[dict] = []
    owasp_contexto: list[str] = []
    owasp_fuentes: list[dict] = []

    if body.max_cves > 0:
        try:
            cve_docs = vector_store.query(
                embeddings,
                settings.chroma_nvd_collection,
                n_results=body.max_cves,
            )
            for doc in cve_docs:
                lines = doc.split("\n")
                cve_id = lines[0].replace("CVE ID: ", "") if lines else "?"
                cves_contexto.append(doc)
                cves_fuentes.append({"id": cve_id, "tipo": "cve", "texto": doc[:200]})
        except Exception as e:
            log.warning("Error consultando ChromaDB (CVEs): %s", e)

    if body.max_exploits > 0:
        try:
            exploit_docs = vector_store.query(
                embeddings,
                settings.chroma_exploit_collection,
                n_results=body.max_exploits,
            )
            for doc in exploit_docs:
                lines = doc.split("\n")
                exploit_id = lines[0] if lines else "?"
                exploits_contexto.append(doc)
                exploits_fuentes.append({"id": exploit_id, "tipo": "exploit", "texto": doc[:200]})
        except Exception as e:
            log.warning("Error consultando ChromaDB (Exploits): %s", e)

    if body.max_owasp > 0:
        try:
            owasp_docs = vector_store.query(
                embeddings,
                settings.chroma_owasp_collection,
                n_results=body.max_owasp,
            )
            for doc in owasp_docs:
                lines = doc.split("\n")
                owasp_title = lines[0].replace("# ", "") if lines else "?"
                owasp_contexto.append(doc)
                owasp_fuentes.append({"id": owasp_title, "tipo": "owasp", "texto": doc[:200]})
        except Exception as e:
            log.warning("Error consultando ChromaDB (OWASP): %s", e)

    partes = []
    if cves_contexto:
        partes.append("VULNERABILIDADES RELEVANTES (CVE):\n" + "\n---\n".join(cves_contexto))
    if exploits_contexto:
        partes.append("EXPLOITS RELACIONADOS:\n" + "\n---\n".join(exploits_contexto))
    if owasp_contexto:
        partes.append("OWASP TOP 10 2025:\n" + "\n---\n".join(owasp_contexto))

    return EnrichResponse(
        contexto="\n\n".join(partes),
        fuentes=cves_fuentes + exploits_fuentes + owasp_fuentes,
        total_cves=len(cves_contexto),
        total_exploits=len(exploits_contexto),
        total_owasp=len(owasp_contexto),
    )
