#!/usr/bin/env python3
"""
Descarga CVEs de NVD, las almacena en MongoDB (NoSQL) y
genera embeddings en ChromaDB para búsqueda RAG.
"""
import datetime
import requests
import chromadb
import mongo_integration as mongo
from config import (
    CHROMA_HOST, CHROMA_PORT, CHROMA_NVD_COLLECTION,
    NVD_BATCH_SIZE, NVD_LAST_UPDATE_FILE,
    fetch_cves_recent, generate_embeddings_batch,
    get_chroma_existing_ids, set_last_update_date,
    generate_single_embedding,
)


def check_embedding_endpoint():
    from config import EMBEDDING_MODEL, OLLAMA_BASE_URL
    print("Verificando endpoint de embeddings...")
    try:
        r = requests.post(f"{OLLAMA_BASE_URL}/api/embed",
                          json={"model": EMBEDDING_MODEL, "input": ["test"]},
                          timeout=60)
        if r.status_code == 200 and "embeddings" in r.json():
            print("✅ Endpoint /api/embed listo.")
        else:
            print(f"⚠️ El endpoint /api/embed no respondió correctamente.")
            return False
    except Exception as e:
        print(f"⚠️ No se pudo conectar: {e}")
        return False
    return True


def main():
    print("Verificando conexión a MongoDB...")
    if not mongo.ping():
        print("⚠️ No se pudo conectar a MongoDB. Asegúrate de que el contenedor esté corriendo.")
        print("   Continuando con ChromaDB solamente...")

    if not check_embedding_endpoint():
        return

    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    collection = client.get_or_create_collection(name=CHROMA_NVD_COLLECTION)

    print("Leyendo CVEs ya almacenadas en ChromaDB...")
    existing_ids = get_chroma_existing_ids(collection)
    print(f"Ya hay {len(existing_ids)} CVEs en ChromaDB.")

    print("🔄 Descargando CVEs recientes...")
    cves = fetch_cves_recent()
    if not cves:
        print("⚠️ No se obtuvieron CVEs.")
        return

    new_cves = [cve for cve in cves if cve['id'] not in existing_ids]
    if not new_cves:
        print("✅ Todas las CVEs ya estaban en la base. ¡Está al día!")
        set_last_update_date()
        return

    print(f"Se añadirán {len(new_cves)} CVEs nuevas de {len(cves)} totales.")

    print(f"💾 Guardando en MongoDB...")
    try:
        mongo.store_cves_bulk(new_cves)
        print(f"   ✅ {len(new_cves)} CVEs almacenadas en MongoDB.")
    except Exception as e:
        print(f"   ⚠️ Error al guardar en MongoDB: {e}")

    docs = []
    ids = []
    for cve in new_cves:
        doc = (f"CVE ID: {cve['id']}\n"
               f"Severidad: {cve['severity']} (CVSS: {cve['score']})\n"
               f"Descripción: {cve['description']}")
        docs.append(doc)
        ids.append(cve['id'])

    total = len(docs)
    print(f"Generando embeddings en lotes de {NVD_BATCH_SIZE}...")

    for start in range(0, total, NVD_BATCH_SIZE):
        end = min(start + NVD_BATCH_SIZE, total)
        batch_docs = docs[start:end]
        batch_ids = ids[start:end]

        embeddings = generate_embeddings_batch(batch_docs)
        if embeddings is None:
            print(f"❌ Fallo en lote {start//NVD_BATCH_SIZE + 1}. Abortando.")
            print(f"   Se detuvo en el ID {batch_ids[0]}. Puedes volver a ejecutar para continuar.")
            return

        try:
            collection.upsert(
                ids=batch_ids,
                documents=batch_docs,
                embeddings=embeddings
            )
            try:
                for cve_id in batch_ids:
                    mongo.get_db()["cves"].update_one(
                        {"id": cve_id},
                        {"$set": {"chromaId": cve_id}}
                    )
            except Exception:
                pass
            print(f"   ✅ Lote {start//NVD_BATCH_SIZE + 1} ({start+1}-{end}/{total}) insertado.")
        except Exception as e:
            print(f"❌ Error al insertar lote {start//NVD_BATCH_SIZE + 1}: {e}")
            return

    set_last_update_date()
    print(f"🎉 Base actualizada. Total CVEs ahora: {len(existing_ids) + total}. ({datetime.date.today()})")


if __name__ == "__main__":
    main()
