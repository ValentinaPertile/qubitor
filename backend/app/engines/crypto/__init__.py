from app.engines.base import Engine, Finding
from app.engines.crypto.classic import scan_classic
from app.engines.crypto.pqc import scan_pqc

class CryptoEngine(Engine):
    name = "crypto"

    def scan(self, repo_path: str) -> list[Finding]:
        findings = []
        # Ejecuta el análisis de Criptografía Clásica (Módulo C)
        findings.extend(scan_classic(repo_path))
        # Ejecuta el análisis de Criptografía Post-Cuántica (Módulo D)
        findings.extend(scan_pqc(repo_path))
        return findings