from pymongo import MongoClient, ASCENDING, TEXT
from pymongo.errors import ConnectionFailure
from config import MONGO_URI, MONGO_DATABASE_NAME, MONGO_TIMEOUT_MS

_client = None
_db = None


def get_client():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=MONGO_TIMEOUT_MS)
    return _client


def get_db():
    global _db
    if _db is None:
        _db = get_client()[MONGO_DATABASE_NAME]
    return _db


def ping():
    try:
        get_client().admin.command('ping')
        return True
    except ConnectionFailure:
        return False


# ---------------------------------------------------------------------------
# CVEs
# ---------------------------------------------------------------------------

def store_cve(cve_data):
    col = get_db()["cves"]
    col.update_one(
        {"id": cve_data["id"]},
        {"$set": {**cve_data, "chromaId": cve_data.get("chromaId", "")}},
        upsert=True
    )
    return col.find_one({"id": cve_data["id"]})


def store_cves_bulk(cves_list):
    col = get_db()["cves"]
    for cve in cves_list:
        col.update_one({"id": cve["id"]}, {"$set": cve}, upsert=True)
    return len(cves_list)


def get_cve(cve_id):
    return get_db()["cves"].find_one({"id": cve_id})


def get_all_cve_ids():
    return [doc["id"] for doc in get_db()["cves"].find({}, {"id": 1})]


def search_cves(query, limit=10):
    col = get_db()["cves"]
    results = col.find({"$text": {"$search": query}}).limit(limit)
    return list(results)


def get_cves_by_chroma_ids(chroma_ids):
    col = get_db()["cves"]
    return list(col.find({"chromaId": {"$in": chroma_ids}}))


# ---------------------------------------------------------------------------
# Exploits (ExploitDB)
# ---------------------------------------------------------------------------

def store_exploit(exploit_data):
    col = get_db()["exploits"]
    col.update_one(
        {"id": exploit_data["id"]},
        {"$set": {**exploit_data, "chromaId": exploit_data.get("chromaId", "")}},
        upsert=True
    )
    return col.find_one({"id": exploit_data["id"]})


def store_exploits_bulk(exploits_list):
    col = get_db()["exploits"]
    for exp in exploits_list:
        col.update_one({"id": exp["id"]}, {"$set": exp}, upsert=True)
    return len(exploits_list)


def get_all_exploit_ids():
    return [doc["id"] for doc in get_db()["exploits"].find({}, {"id": 1})]


def get_exploits_by_chroma_ids(chroma_ids):
    col = get_db()["exploits"]
    return list(col.find({"chromaId": {"$in": chroma_ids}}))


# ---------------------------------------------------------------------------
# Análisis (proyectos escaneados)
# ---------------------------------------------------------------------------

ANALISIS_PENDIENTE = "pendiente"
ANALISIS_EN_PROCESO = "en_proceso"
ANALISIS_COMPLETADO = "completado"
ANALISIS_FALLIDO = "fallido"


def crear_analisis(project_path, total_files=0):
    from datetime import datetime, timezone
    doc = {
        "projectPath": project_path,
        "timestamp": datetime.now(timezone.utc),
        "estado": ANALISIS_PENDIENTE,
        "totalFiles": total_files,
        "archivosAnalizados": 0,
        "taskId": "",
    }
    result = get_db()["analisis"].insert_one(doc)
    return str(result.inserted_id)


def actualizar_estado_analisis(analisis_id, estado, **kwargs):
    from bson.objectid import ObjectId
    update = {"$set": {"estado": estado, **kwargs}}
    get_db()["analisis"].update_one({"_id": ObjectId(analisis_id)}, update)


def get_analisis(analisis_id):
    from bson.objectid import ObjectId
    return get_db()["analisis"].find_one({"_id": ObjectId(analisis_id)})


def listar_analisis(limit=20):
    cursor = get_db()["analisis"].find().sort("timestamp", -1).limit(limit)
    return list(cursor)


# ---------------------------------------------------------------------------
# Hallazgos (vulnerabilidades encontradas por archivo)
# ---------------------------------------------------------------------------

def guardar_hallazgo(analisis_id, filepath, severidad, titulo, descripcion,
                     mitigacion, ubicacion, cve_cwe, raw_response=""):
    doc = {
        "analisisId": analisis_id,
        "filepath": filepath,
        "severidad": severidad,
        "titulo": titulo,
        "descripcion": descripcion,
        "mitigacion": mitigacion,
        "ubicacion": ubicacion,
        "cve_cwe": cve_cwe,
        "raw_response": raw_response,
    }
    result = get_db()["hallazgos"].insert_one(doc)
    return str(result.inserted_id)


def get_hallazgos(analisis_id):
    from bson.objectid import ObjectId
    return list(get_db()["hallazgos"].find({"analisisId": analisis_id}))


def get_hallazgos_por_severidad(analisis_id):
    from bson.objectid import ObjectId
    pipeline = [
        {"$match": {"analisisId": analisis_id}},
        {"$group": {"_id": "$severidad", "count": {"$sum": 1}}}
    ]
    return list(get_db()["hallazgos"].aggregate(pipeline))
