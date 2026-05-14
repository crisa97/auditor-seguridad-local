#!/usr/bin/env python3
import datetime, time
import requests
import chromadb

EMBED_MODEL = "nomic-embed-text"
COLLECTION_NAME = "nvd_vulnerabilities"
OLLAMA_URL = "http://localhost:11434"
CHROMA_HOST = "localhost"
CHROMA_PORT = "8001"
LAST_UPDATE_FILE = "last_nvd_update.txt"

BATCH_SIZE = 200                # más pequeño para evitar timeouts
EMBED_TIMEOUT = 300            # hasta 5 minutos por lote si es necesario
MAX_RETRIES = 2
API_TIMEOUT = 30

def fetch_cves_recent(days=90):
    """Obtiene todas las CVEs de los últimos 'days' días."""
    end_date = datetime.datetime.now(datetime.timezone.utc)
    start_date = end_date - datetime.timedelta(days=days)
    start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'pubStartDate': start_str,
        'pubEndDate': end_str,
        'resultsPerPage': 2000
    }
    all_cves = []
    while True:
        try:
            response = requests.get(base_url, params=params, timeout=API_TIMEOUT)
        except Exception as e:
            print(f"Error al conectar con la API NVD: {e}")
            break
        if response.status_code == 404:
            break
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            cve = vuln['cve']
            desc = "Sin descripción"
            for d in cve.get('descriptions', []):
                if d['lang'] == 'en':
                    desc = d['value']
                    break
            metrics = cve.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
            severity = cvss_v3.get('baseSeverity', 'N/A')
            score = cvss_v3.get('baseScore', 'N/A')
            cve_info = {
                'id': cve['id'],
                'description': desc,
                'severity': severity,
                'score': score
            }
            all_cves.append(cve_info)

        total_results = data.get('totalResults', 0)
        if len(all_cves) >= total_results:
            break
        params['startIndex'] = data.get('startIndex', 0) + data.get('resultsPerPage', 0)
        time.sleep(0.6)
    return all_cves

def generate_embeddings_batch(texts):
    payload = {"model": EMBED_MODEL, "input": texts}
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.post(f"{OLLAMA_URL}/api/embed", json=payload, timeout=EMBED_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            if "embeddings" in data:
                return data["embeddings"]
            else:
                print(f"Intento {attempt+1}: respuesta sin 'embeddings'.")
        except requests.Timeout:
            print(f"Intento {attempt+1}: timeout ({EMBED_TIMEOUT}s).", end="")
            if attempt < MAX_RETRIES - 1:
                print(" Reintentando...")
                time.sleep(5)
            else:
                print(" No más reintentos.")
        except Exception as e:
            print(f"Intento {attempt+1}: error {e}")
            break
    return None

def main():
    # Verificar endpoint
    print("Verificando endpoint de embeddings...")
    try:
        r = requests.post(f"{OLLAMA_URL}/api/embed",
                          json={"model": EMBED_MODEL, "input": ["test"]},
                          timeout=60)
        if r.status_code == 200 and "embeddings" in r.json():
            print("✅ Endpoint /api/embed listo.")
        else:
            print(f"⚠️ El endpoint /api/embed no respondió correctamente.")
            return
    except Exception as e:
        print(f"⚠️ No se pudo conectar: {e}")
        return

    # Conectar a ChromaDB
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    # Saber qué IDs ya existen
    print("Leyendo CVEs ya almacenadas...")
    existing_ids = set()
    # Para colecciones grandes podemos hacer fetch de todos los IDs con get()
    # get() devuelve hasta 1000 por defecto, necesitamos paginar.
    # Vamos a ir recuperando todos los IDs
    offset = 0
    while True:
        batch = collection.get(limit=1000, offset=offset, include=[])
        if not batch['ids']:
            break
        existing_ids.update(batch['ids'])
        offset += len(batch['ids'])
    print(f"Ya hay {len(existing_ids)} CVEs insertadas.")

    # Obtener CVEs actualizadas
    print("🔄 Descargando CVEs recientes...")
    cves = fetch_cves_recent(days=90)
    if not cves:
        print("⚠️ No se obtuvieron CVEs.")
        return

    # Filtrar solo las que faltan
    new_cves = [cve for cve in cves if cve['id'] not in existing_ids]
    if not new_cves:
        print("✅ Todas las CVEs ya estaban en la base. ¡Está al día!")
        with open(LAST_UPDATE_FILE, "w") as f:
            f.write(datetime.date.today().isoformat())
        return

    print(f"Se añadirán {len(new_cves)} CVEs nuevas de {len(cves)} totales.")

    # Preparar documentos
    docs = []
    ids = []
    for cve in new_cves:
        doc = (f"CVE ID: {cve['id']}\n"
               f"Severidad: {cve['severity']} (CVSS: {cve['score']})\n"
               f"Descripción: {cve['description']}")
        docs.append(doc)
        ids.append(cve['id'])

    total = len(docs)
    print(f"Generando embeddings en lotes de {BATCH_SIZE}...")

    for start in range(0, total, BATCH_SIZE):
        end = min(start + BATCH_SIZE, total)
        batch_docs = docs[start:end]
        batch_ids = ids[start:end]

        embeddings = generate_embeddings_batch(batch_docs)
        if embeddings is None:
            print(f"❌ Fallo en lote {start//BATCH_SIZE + 1}. Abortando.")
            print(f"   Se detuvo en el ID {batch_ids[0]}. Puedes volver a ejecutar el script para continuar.")
            return

        try:
            collection.upsert(
                ids=batch_ids,
                documents=batch_docs,
                embeddings=embeddings
            )
            print(f"   ✅ Lote {start//BATCH_SIZE + 1} ({start+1}-{end}/{total}) insertado.")
        except Exception as e:
            print(f"❌ Error al insertar lote {start//BATCH_SIZE + 1}: {e}")
            return

    with open(LAST_UPDATE_FILE, "w") as f:
        f.write(datetime.date.today().isoformat())
    print(f"🎉 Base actualizada. Total CVEs ahora: {len(existing_ids) + total}. ({datetime.date.today()})")

if __name__ == "__main__":
    main()
