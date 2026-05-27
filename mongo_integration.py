"""
Wrapper backward-compatible con inicializacion perezosa (lazy).
"""
from src.adapters.mongodb.connection import MongoConnection
from src.adapters.mongodb.cve_repository import MongoCveRepository, MongoExploitRepository
from src.adapters.mongodb.hallazgo_repository import MongoHallazgoRepository, MongoAnalisisRepository
from src.domain.enums import EstadoAnalisis

ANALISIS_PENDIENTE = EstadoAnalisis.PENDIENTE
ANALISIS_EN_PROCESO = EstadoAnalisis.EN_PROCESO
ANALISIS_COMPLETADO = EstadoAnalisis.COMPLETADO
ANALISIS_FALLIDO = EstadoAnalisis.FALLIDO

_cve_repo = None
_exploit_repo = None
_hallazgo_repo = None
_analisis_repo = None


def _get_cve_repo():
    global _cve_repo
    if _cve_repo is None:
        _cve_repo = MongoCveRepository()
    return _cve_repo


def _get_exploit_repo():
    global _exploit_repo
    if _exploit_repo is None:
        _exploit_repo = MongoExploitRepository()
    return _exploit_repo


def _get_hallazgo_repo():
    global _hallazgo_repo
    if _hallazgo_repo is None:
        _hallazgo_repo = MongoHallazgoRepository()
    return _hallazgo_repo


def _get_analisis_repo():
    global _analisis_repo
    if _analisis_repo is None:
        _analisis_repo = MongoAnalisisRepository()
    return _analisis_repo


get_client = MongoConnection.get_client
get_db = MongoConnection.get_db
ping = MongoConnection.ping

store_cve = lambda cve: _get_cve_repo().store(cve)
store_cves_bulk = lambda cves: _get_cve_repo().store_bulk(cves)
get_cve = lambda cve_id: _get_cve_repo().get_by_id(cve_id)
get_all_cve_ids = lambda: _get_cve_repo().get_all_ids()
get_cves_by_chroma_ids = lambda ids: _get_cve_repo().get_by_chroma_ids(ids)

store_exploit = lambda exp: _get_exploit_repo().store(exp)
store_exploits_bulk = lambda exps: _get_exploit_repo().store_bulk(exps)
get_all_exploit_ids = lambda: _get_exploit_repo().get_all_ids()
get_exploits_by_chroma_ids = lambda ids: _get_exploit_repo().get_by_chroma_ids(ids)

guardar_hallazgo = lambda h: _get_hallazgo_repo().store(h)
get_hallazgos = lambda aid: _get_hallazgo_repo().get_by_analisis(aid)
get_hallazgos_por_severidad = lambda aid: _get_hallazgo_repo().get_severidad_counts(aid)

crear_analisis = lambda pp, tf=0: _get_analisis_repo().create(pp, tf)
actualizar_estado_analisis = lambda aid, est, **kw: _get_analisis_repo().update_state(aid, est, **kw)
get_analisis = lambda aid: _get_analisis_repo().get_by_id(aid)
listar_analisis = lambda lim=20: _get_analisis_repo().list_all(lim)
