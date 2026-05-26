"""
Wrapper backward-compatible.
"""
from src.adapters.mongodb.connection import MongoConnection
from src.adapters.mongodb.cve_repository import MongoCveRepository, MongoExploitRepository
from src.adapters.mongodb.hallazgo_repository import MongoHallazgoRepository, MongoAnalisisRepository
from src.domain.enums import EstadoAnalisis

ANALISIS_PENDIENTE = EstadoAnalisis.PENDIENTE
ANALISIS_EN_PROCESO = EstadoAnalisis.EN_PROCESO
ANALISIS_COMPLETADO = EstadoAnalisis.COMPLETADO
ANALISIS_FALLIDO = EstadoAnalisis.FALLIDO

_cve_repo = MongoCveRepository()
_exploit_repo = MongoExploitRepository()
_hallazgo_repo = MongoHallazgoRepository()
_analisis_repo = MongoAnalisisRepository()

get_client = MongoConnection.get_client
get_db = MongoConnection.get_db
ping = MongoConnection.ping

store_cve = _cve_repo.store
store_cves_bulk = _cve_repo.store_bulk
get_cve = _cve_repo.get_by_id
get_all_cve_ids = _cve_repo.get_all_ids
get_cves_by_chroma_ids = _cve_repo.get_by_chroma_ids

store_exploit = _exploit_repo.store
store_exploits_bulk = _exploit_repo.store_bulk
get_all_exploit_ids = _exploit_repo.get_all_ids
get_exploits_by_chroma_ids = _exploit_repo.get_by_chroma_ids

guardar_hallazgo = _hallazgo_repo.store
get_hallazgos = _hallazgo_repo.get_by_analisis
get_hallazgos_por_severidad = _hallazgo_repo.get_severidad_counts

crear_analisis = _analisis_repo.create
actualizar_estado_analisis = _analisis_repo.update_state
get_analisis = _analisis_repo.get_by_id
listar_analisis = _analisis_repo.list_all
