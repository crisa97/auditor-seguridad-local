"""
Contenedor de inyeccion de dependencias (Dependency Injection).
Centraliza la construccion del grafo de dependencias.
"""


class DIContainer:
    _instances: dict = {}

    @classmethod
    def get(cls, key: str, factory):
        if key not in cls._instances:
            cls._instances[key] = factory()
        return cls._instances[key]

    @classmethod
    def reset(cls):
        cls._instances = {}


# ---------------------------------------------------------------------------
# Factories perezosas (lazy)
# ---------------------------------------------------------------------------

def get_vector_store():
    from src.adapters.chromadb.vector_store import ChromaVectorStore
    return DIContainer.get("vector_store", ChromaVectorStore)


def get_embedding_service():
    from src.adapters.ollama.embedding_service import OllamaEmbeddingService
    return DIContainer.get("embedding_service", OllamaEmbeddingService)


def get_llm_service():
    from src.adapters.ollama.llm_service import OllamaLlmService
    return DIContainer.get("llm_service", OllamaLlmService)


def get_cve_repository():
    from src.adapters.mongodb.cve_repository import MongoCveRepository
    return DIContainer.get("cve_repo", MongoCveRepository)


def get_hallazgo_repository():
    from src.adapters.mongodb.hallazgo_repository import MongoHallazgoRepository
    return DIContainer.get("hallazgo_repo", MongoHallazgoRepository)


def get_analisis_repository():
    from src.adapters.mongodb.hallazgo_repository import MongoAnalisisRepository
    return DIContainer.get("analisis_repo", MongoAnalisisRepository)


def get_apikey_repository():
    from src.adapters.postgresql.apikey_repository import PostgresApiKeyRepository
    return DIContainer.get("apikey_repo", PostgresApiKeyRepository)


def get_conocimiento_repository():
    from src.adapters.postgresql.conocimiento_repository import PostgresConocimientoRepository
    return DIContainer.get("conocimiento_repo", PostgresConocimientoRepository)


def get_afirmacion_extractor():
    from src.adapters.afirmaciones.extractor import RegexAfirmacionExtractor
    return DIContainer.get("extractor", RegexAfirmacionExtractor)


def get_report_generator():
    from src.adapters.pdf.report_generator import PdfReportGenerator
    return DIContainer.get("report_gen", PdfReportGenerator)


def get_analizador():
    from src.application.analizador import AnalizarProyecto
    return DIContainer.get("analizador", lambda: AnalizarProyecto(
        llm=get_llm_service(),
        embed=get_embedding_service(),
        vector_store=get_vector_store(),
        hallazgo_repo=get_hallazgo_repository(),
        analisis_repo=get_analisis_repository(),
        cve_repo=get_cve_repository(),
        report_gen=get_report_generator(),
    ))


def get_validar_api_key():
    from src.application.validador import ValidarApiKey
    return DIContainer.get("validar_apikey", lambda: ValidarApiKey(
        api_key_repo=get_apikey_repository(),
    ))


def get_validar_afirmacion():
    from src.application.validador import ValidarAfirmacion
    return DIContainer.get("validar_afirmacion", lambda: ValidarAfirmacion(
        conocimiento_repo=get_conocimiento_repository(),
        extractor=get_afirmacion_extractor(),
    ))


def get_sincronizador_nvd():
    from src.application.sincronizador import SincronizarNvd
    return DIContainer.get("sincronizador_nvd", lambda: SincronizarNvd(
        cve_repo=get_cve_repository(),
        embed=get_embedding_service(),
        vector_store=get_vector_store(),
    ))


def get_indexador_exploitdb():
    from src.application.sincronizador import IndexarExploitDb
    return DIContainer.get("indexador_exploitdb", lambda: IndexarExploitDb(
        exploit_repo=get_cve_repository(),  # ExploitDB usa misma interface
        embed=get_embedding_service(),
        vector_store=get_vector_store(),
    ))
