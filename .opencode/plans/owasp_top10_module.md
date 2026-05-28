# Plan: Módulo OWASP Top 10 2025

## Archivos a modificar/crear

### 1. `src/domain/models.py` — Añadir dataclass

```python
@dataclass
class OwaspTop10Entry:
    id: str
    category: str
    title: str
    content: str
    risk_rank: str = ""
    cwes: str = ""
    chroma_id: str = ""
```

Insertar antes de `@dataclass class Afirmacion:`.

### 2. `src/ports/repositories.py` — Añadir interfaz

```python
class IOwaspTop10Repository(ABC):
    @abstractmethod
    def store(self, entry: OwaspTop10Entry) -> None: ...

    @abstractmethod
    def store_bulk(self, entries: list[OwaspTop10Entry]) -> int: ...

    @abstractmethod
    def get_all_ids(self) -> list[str]: ...

    @abstractmethod
    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[OwaspTop10Entry]: ...
```

- Actualizar import: `OwaspTop10Entry`
- Insertar antes de `class IConocimientoRepository(ABC):`

### 3. `src/adapters/mongodb/owasp_repository.py` — Nuevo archivo

```python
from pymongo import UpdateOne
from src.domain.models import OwaspTop10Entry
from src.ports.repositories import IOwaspTop10Repository
from src.adapters.mongodb.connection import MongoConnection


class MongoOwaspTop10Repository(IOwaspTop10Repository):
    def __init__(self):
        self._col = MongoConnection.get_db()["owasp_top10"]

    def store(self, entry: OwaspTop10Entry) -> None:
        self._col.update_one(
            {"id": entry.id},
            {"$set": {
                "id": entry.id,
                "category": entry.category,
                "title": entry.title,
                "content": entry.content,
                "risk_rank": entry.risk_rank,
                "cwes": entry.cwes,
                "chromaId": entry.chroma_id,
            }},
            upsert=True,
        )

    def store_bulk(self, entries: list[OwaspTop10Entry]) -> int:
        if not entries:
            return 0
        operations = [
            UpdateOne({"id": e.id}, {"$set": {
                "id": e.id,
                "category": e.category,
                "title": e.title,
                "content": e.content,
                "risk_rank": e.risk_rank,
                "cwes": e.cwes,
                "chromaId": e.chroma_id,
            }}, upsert=True)
            for e in entries
        ]
        self._col.bulk_write(operations)
        return len(entries)

    def get_all_ids(self) -> list[str]:
        return [doc["id"] for doc in self._col.find({}, {"id": 1})]

    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[OwaspTop10Entry]:
        docs = self._col.find({"chromaId": {"$in": chroma_ids}})
        return [
            OwaspTop10Entry(
                id=d["id"],
                category=d.get("category", ""),
                title=d.get("title", ""),
                content=d.get("content", ""),
                risk_rank=d.get("risk_rank", ""),
                cwes=d.get("cwes", ""),
                chroma_id=d.get("chromaId", ""),
            )
            for d in docs
        ]
```

### 4. `src/application/sincronizador.py` — Añadir clase `IndexarOwaspTop10`

Insertar después de la clase `IndexarExploitDb` (antes del EOF).

```python
class IndexarOwaspTop10:
    def __init__(
        self,
        owasp_repo: IOwaspTop10Repository,
        embed: IEmbeddingService,
        vector_store: IVectorStore,
    ):
        self._owasp_repo = owasp_repo
        self._embed = embed
        self._vector_store = vector_store

    def _clone_or_update_repo(self) -> None:
        if not os.path.exists(settings.owasp_local_dir):
            print(f"Clonando {settings.owasp_repo_url} ...")
            subprocess.run(
                ["git", "clone", "--depth", "1", settings.owasp_repo_url, settings.owasp_local_dir],
                check=True,
            )
        else:
            print("Actualizando repositorio local de OWASP Top10...")
            subprocess.run(["git", "-C", settings.owasp_local_dir, "pull"], check=True)

    def _parse_files(self) -> list[dict]:
        docs_dir = os.path.join(settings.owasp_local_dir, "2025", "docs", "en")
        if not os.path.isdir(docs_dir):
            raise FileNotFoundError(f"No se encontro la carpeta {docs_dir}")

        CATEGORY_MAP = {
            "0x00": "introduction",
            "0x01": "about_owasp",
            "0x02": "risk_methodology",
            "0x03": "appsec_program",
            "A01": "broken_access_control",
            "A02": "security_misconfiguration",
            "A03": "supply_chain",
            "A04": "cryptographic_failures",
            "A05": "injection",
            "A06": "insecure_design",
            "A07": "authentication_failures",
            "A08": "integrity_failures",
            "A09": "logging_failures",
            "A10": "exceptional_conditions",
            "X01": "next_steps",
        }

        documents: list[dict] = []
        for fname in sorted(os.listdir(docs_dir)):
            if not fname.endswith(".md"):
                continue
            path = os.path.join(docs_dir, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                if not text.strip():
                    continue

                prefix = fname.split("_")[0] if "_" in fname else fname.replace(".md", "")
                category = CATEGORY_MAP.get(prefix, fname.replace(".md", ""))

                # Extraer título del primer heading
                title = category.replace("_", " ").title()
                for line in text.split("\n"):
                    if line.startswith("# ") and len(line) > 2:
                        title = line[2:].strip()
                        break

                # Extraer ranking de riesgo del nombre (A01-A10)
                risk_rank = ""
                if fname.startswith("A"):
                    risk_rank = fname[1:3]  # "01", "02", ...

                doc_id = f"owasp_2025_{prefix.lower()}"
                documents.append({
                    "id": doc_id,
                    "category": category,
                    "title": title,
                    "content": text[:settings.owasp_max_text_length],
                    "risk_rank": risk_rank,
                    "cwes": "",
                })
            except Exception as e:
                logger.warning("No se pudo leer archivo OWASP %s: %s", path, e)
        return documents

    def execute(self) -> None:
        print("=== Indexando OWASP Top 10 2025 en MongoDB + ChromaDB ===")

        self._clone_or_update_repo()

        print("Extrayendo documentos OWASP Top 10...")
        docs = self._parse_files()
        print(f"Se encontraron {len(docs)} documentos.")

        if not docs:
            print("No se encontraron documentos. Abortando.")
            return

        print("Guardando en MongoDB...")
        try:
            self._owasp_repo.store_bulk([
                OwaspTop10Entry(
                    id=d['id'],
                    category=d['category'],
                    title=d['title'],
                    content=d['content'],
                    risk_rank=d['risk_rank'],
                    cwes=d['cwes'],
                )
                for d in docs
            ])
            print(f"   OK {len(docs)} documentos almacenados en MongoDB.")
        except Exception as e:
            print(f"   Error al guardar en MongoDB: {e}")

        existing_ids = self._vector_store.get_existing_ids(settings.chroma_owasp_collection)
        print(f"Ya existen {len(existing_ids)} documentos en ChromaDB.")

        new_docs = [d for d in docs if d['id'] not in existing_ids]
        if not new_docs:
            print("Todos los documentos ya estaban indexados.")
            return

        print(f"Se indexaran {len(new_docs)} nuevos documentos.")

        batch_size = settings.owasp_batch_size
        total = len(new_docs)

        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            batch = new_docs[start:end]
            ids = [d['id'] for d in batch]
            texts = [d['content'] for d in batch]
            metadatas = [{"category": d['category'], "title": d['title'], "risk_rank": d['risk_rank']} for d in batch]

            embeddings = self._embed.generate_batch(texts)
            if embeddings is None:
                print(f"Fallo en lote {start // batch_size + 1}. Abortando.")
                return

            try:
                self._vector_store.upsert(
                    settings.chroma_owasp_collection,
                    ids=ids, documents=texts,
                    embeddings=embeddings,
                    metadatas=metadatas,
                )
                print(f"   OK Lote {start // batch_size + 1} ({start + 1}-{end}/{total}) insertado.")
            except Exception as e:
                print(f"Error en lote {start // batch_size + 1}: {e}")
                return

        print(f"Indexacion completada. Total: {len(existing_ids) + total} documentos.")
```

Actualizar imports al inicio del archivo:

```python
from src.domain.models import Cve, Exploit, OwaspTop10Entry
from src.ports.repositories import ICveRepository, IExploitRepository, IOwaspTop10Repository
```

### 5. `src/infrastructure/config.py` — Añadir settings OWASP

Insertar después de la sección `# ExploitDB` (después de `exploit_max_text_length`):

```python
    # OWASP Top 10
    owasp_repo_url: str = field(default_factory=lambda: os.getenv("OWASP_REPO_URL", "https://github.com/OWASP/Top10.git"))
    owasp_local_dir: str = field(default_factory=lambda: os.getenv("OWASP_LOCAL_DIR", "./owasp-top10-local"))
    owasp_batch_size: int = field(default_factory=lambda: int(os.getenv("OWASP_BATCH_SIZE", "16")))
    owasp_max_text_length: int = field(default_factory=lambda: int(os.getenv("OWASP_MAX_TEXT_LENGTH", "50000")))
```

### 6. `src/infrastructure/di.py` — Añadir factory

Insertar después de `get_indexador_exploitdb()`:

```python
def get_owasp_top10_repository():
    from src.adapters.mongodb.owasp_repository import MongoOwaspTop10Repository
    return DIContainer.get("owasp_repo", MongoOwaspTop10Repository)


def get_indexador_owasp_top10():
    from src.application.sincronizador import IndexarOwaspTop10
    return DIContainer.get("indexador_owasp_top10", lambda: IndexarOwaspTop10(
        owasp_repo=get_owasp_top10_repository(),
        embed=get_embedding_service(),
        vector_store=get_vector_store(),
    ))
```

### 7. `index_owasp_top10.py` — Nuevo archivo raíz

```python
#!/usr/bin/env python3
"""
Wrapper backward-compatible para indexar OWASP Top 10 2025.
"""
from src.infrastructure.di import get_indexador_owasp_top10
from src.adapters.mongodb.connection import MongoConnection


def main():
    print("Verificando conexion a MongoDB...")
    if not MongoConnection.ping():
        print("No se pudo conectar a MongoDB.")
        return

    idx = get_indexador_owasp_top10()
    idx.execute()


if __name__ == "__main__":
    main()
```

### 8. `init-mongo.js` — Añadir colección

Insertar después de la creación de `hallazgos`:

```javascript
db.createCollection('owasp_top10');

db.owasp_top10.createIndex({ id: 1 }, { unique: true });
db.owasp_top10.createIndex({ category: 1 });
db.owasp_top10.createIndex({ risk_rank: 1 });
db.owasp_top10.createIndex({ chromaId: 1 });
db.owasp_top10.createIndex({ '$**': 'text' });
```

### 9. `.env.example` — Añadir vars OWASP

Insertar después de la sección `# ExploitDB`:

```env
# ── OWASP Top 10 ─────────────────────────────────
OWASP_REPO_URL=https://github.com/OWASP/Top10.git
OWASP_LOCAL_DIR=./owasp-top10-local
OWASP_BATCH_SIZE=16
OWASP_MAX_TEXT_LENGTH=50000
CHROMA_OWASP_COLLECTION=owasp_top10_2025
```

### 10. `.env` — Añadir defaults

```env
OWASP_REPO_URL=https://github.com/OWASP/Top10.git
OWASP_LOCAL_DIR=./owasp-top10-local
OWASP_BATCH_SIZE=16
OWASP_MAX_TEXT_LENGTH=50000
CHROMA_OWASP_COLLECTION=owasp_top10_2025
```

### 11. `src/interfaces/api/routers/enrich.py` — Actualizar endpoint

Añadir campo `max_owasp` al request model:

```python
    max_owasp: int = Field(default=3, ge=0, le=10, description="Maximo de docs OWASP a incluir (0 = ninguno)")
```

Añadir campo `total_owasp` al response model:

```python
    total_owasp: int = 0
```

Añadir lógica entre CVEs y Exploits:

```python
    owasp_contexto: list[str] = []
    owasp_fuentes: list[dict] = []

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
```

Añadir al response:

```python
    if owasp_contexto:
        partes.append("OWASP TOP 10 2025:\n" + "\n---\n".join(owasp_contexto))

    return EnrichResponse(
        ...
        total_owasp=len(owasp_contexto),
    )
```

## Orden de implementación

1. `src/domain/models.py`
2. `src/ports/repositories.py`
3. `src/adapters/mongodb/owasp_repository.py` (nuevo)
4. `src/application/sincronizador.py`
5. `src/infrastructure/config.py`
6. `src/infrastructure/di.py`
7. `index_owasp_top10.py` (nuevo)
8. `init-mongo.js`
9. `.env.example` + `.env`
10. `src/interfaces/api/routers/enrich.py`

## Verificación

```bash
python -m pytest tests/ -v                          # 36 tests deben seguir pasando
python index_owasp_top10.py                         # Indexar OWASP Top 10
curl -s -X POST http://127.0.0.1:8000/api/v1/rag/enrichir \
  -H "Content-Type: application/json" \
  -d '{"texto":"authentication bypass","api_key":"insecure-change-me","max_owasp":3}'  # Verificar OWASP en respuesta
```
