from abc import ABC, abstractmethod
from typing import Optional

from src.domain.models import Cve, Exploit, Hallazgo, Analisis, ApiKey, Afirmacion, OwaspTop10Entry


class ICveRepository(ABC):
    @abstractmethod
    def get_by_id(self, cve_id: str) -> Optional[Cve]: ...

    @abstractmethod
    def store(self, cve: Cve) -> None: ...

    @abstractmethod
    def store_bulk(self, cves: list[Cve]) -> int: ...

    @abstractmethod
    def get_all_ids(self) -> list[str]: ...

    @abstractmethod
    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[Cve]: ...


class IExploitRepository(ABC):
    @abstractmethod
    def store(self, exploit: Exploit) -> None: ...

    @abstractmethod
    def store_bulk(self, exploits: list[Exploit]) -> int: ...

    @abstractmethod
    def get_all_ids(self) -> list[str]: ...

    @abstractmethod
    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[Exploit]: ...


class IHallazgoRepository(ABC):
    @abstractmethod
    def store(self, hallazgo: Hallazgo) -> str: ...

    @abstractmethod
    def get_by_analisis(self, analisis_id: str) -> list[Hallazgo]: ...

    @abstractmethod
    def get_severidad_counts(self, analisis_id: str) -> dict[str, int]: ...


class IAnalisisRepository(ABC):
    @abstractmethod
    def create(self, project_path: str, total_files: int = 0, usuario_id: int = 0) -> str: ...

    @abstractmethod
    def update_state(self, analisis_id: str, estado: str, **kwargs) -> None: ...

    @abstractmethod
    def get_by_id(self, analisis_id: str) -> Optional[Analisis]: ...

    @abstractmethod
    def list_all(self, limit: int = 20) -> list[Analisis]: ...

    @abstractmethod
    def store_pdf(self, analisis_id: str, pdf_bytes: bytes) -> None: ...

    @abstractmethod
    def get_pdf(self, analisis_id: str) -> Optional[bytes]: ...


class IApiKeyRepository(ABC):
    @abstractmethod
    def get_by_hash(self, key_hash: str) -> Optional[ApiKey]: ...

    @abstractmethod
    def store(self, api_key: ApiKey) -> None: ...

    @abstractmethod
    def update_ultimo_uso(self, key_hash: str) -> None: ...


class IOwaspTop10Repository(ABC):
    @abstractmethod
    def store(self, entry: OwaspTop10Entry) -> None: ...

    @abstractmethod
    def store_bulk(self, entries: list[OwaspTop10Entry]) -> int: ...

    @abstractmethod
    def get_all_ids(self) -> list[str]: ...

    @abstractmethod
    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[OwaspTop10Entry]: ...


class IConocimientoRepository(ABC):
    @abstractmethod
    def get_by_texto(self, texto: str) -> Optional[Afirmacion]: ...

    @abstractmethod
    def registrar_pendiente(self, texto: str, consulta: str = "", modelo: str = "") -> bool: ...
