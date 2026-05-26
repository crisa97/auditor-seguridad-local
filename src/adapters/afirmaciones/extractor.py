import re

from src.ports.services import IAfirmacionExtractor


class RegexAfirmacionExtractor(IAfirmacionExtractor):
    _PATTERNS = [
        re.compile(r'(?:El|La|Los|Las)\s+\w+\s+(?:es|son|está|están|tiene|tienen|puede|pueden|debe|deben)\s+\w+', re.IGNORECASE),
        re.compile(r'(?:Se\s+(?:sabe|considera|conoce|sabe\s+que|dice\s+que))\s+.+', re.IGNORECASE),
        re.compile(r'(?:Esto\s+(?:es|significa|implica|indica|muestra))\s+.+', re.IGNORECASE),
        re.compile(r'\w+\s+(?:es|son)\s+(?:un|una|el|la|los|las)\s+\w+', re.IGNORECASE),
        re.compile(r'(?:No\s+(?:es|son|existe|tiene))\s+.+', re.IGNORECASE),
    ]

    def extract(self, texto: str) -> list[str]:
        afirmaciones: set[str] = set()
        for pattern in self._PATTERNS:
            for match in pattern.finditer(texto):
                afirmacion = match.group(0).strip().rstrip('.!,;')
                if len(afirmacion) > 15:
                    afirmaciones.add(afirmacion.lower())
        return list(afirmaciones)
