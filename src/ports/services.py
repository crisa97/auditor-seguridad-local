from abc import ABC, abstractmethod
from typing import Optional


class ILlmService(ABC):
    @abstractmethod
    def generate(self, prompt: str, model: str, **options) -> str: ...


class IEmbeddingService(ABC):
    @abstractmethod
    def generate(self, text: str) -> Optional[list[float]]: ...

    @abstractmethod
    def generate_batch(self, texts: list[str]) -> Optional[list[list[float]]]: ...


class IVectorStore(ABC):
    @abstractmethod
    def query(self, embedding: list[float], collection_name: str, n_results: int = 3) -> list[str]: ...

    @abstractmethod
    def get_existing_ids(self, collection_name: str) -> set[str]: ...

    @abstractmethod
    def upsert(self, collection_name: str, ids: list[str], documents: list[str],
               embeddings: list[list[float]], metadatas: Optional[list[dict]] = None) -> None: ...


class IAfirmacionExtractor(ABC):
    @abstractmethod
    def extract(self, texto: str) -> list[str]: ...


class IReportGenerator(ABC):
    @abstractmethod
    def generate_pdf(self, report_text: str, output_path: str) -> None: ...

    @abstractmethod
    def generate_txt(self, report_text: str, output_path: str) -> None: ...
