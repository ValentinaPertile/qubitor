"""Inventario criptográfico (CBOM) en formato CycloneDX 1.6 (Módulo D).

CycloneDX 1.6 incorpora los activos criptográficos (`cryptographic-asset`): cada
algoritmo detectado es un componente con su primitiva, su nivel de seguridad
clásico y cuántico, y los lugares del código donde aparece. Así el inventario
se puede abrir con cualquier herramienta que lea CycloneDX.

Especificación: https://cyclonedx.org/docs/1.6/json/
"""

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.engines.base import Finding, Severity

SPEC_VERSION = "1.6"
REPOSITORY_REF = "repository"

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass(frozen=True)
class _Profile:
    primitive: str  # enum `primitive` de CycloneDX
    functions: tuple[str, ...]  # enum `cryptoFunctions` de CycloneDX
    mode: str | None = None


# Qué tipo de criptografía es cada regla de pqc.py y classic.py.
_RULE_PROFILES: dict[str, _Profile] = {
    "crypto.pqc.rsa-keygen": _Profile("pke", ("keygen",)),
    # Una clave EC generada sin más contexto puede servir para firmar o para acordar claves.
    "crypto.pqc.ec-keygen": _Profile("unknown", ("keygen",)),
    "crypto.pqc.ecdsa": _Profile("signature", ("sign",)),
    "crypto.pqc.eddsa": _Profile("signature", ("sign",)),
    "crypto.pqc.ecdh": _Profile("key-agree", ("keyderive",)),
    "crypto.pqc.dh": _Profile("key-agree", ("keyderive",)),
    "crypto.pqc.dsa-keygen": _Profile("signature", ("keygen",)),
    "crypto.pqc.aes-128": _Profile("block-cipher", ("encrypt", "decrypt")),
    "crypto.pqc.inventory.aes": _Profile("block-cipher", ("encrypt", "decrypt")),
    "crypto.pqc.inventory.hash": _Profile("hash", ("digest",)),
    "crypto.pqc.inventory.password-hash": _Profile("kdf", ("keyderive",)),
    "crypto.pqc.inventory.chacha20": _Profile("ae", ("encrypt", "decrypt")),
    "crypto.classic.weak-hash": _Profile("hash", ("digest",)),
    "crypto.classic.weak-cipher": _Profile("block-cipher", ("encrypt", "decrypt")),
    "crypto.classic.aes-ecb": _Profile("block-cipher", ("encrypt", "decrypt"), mode="ecb"),
    "crypto.classic.rsa-weak-key": _Profile("pke", ("keygen",)),
    "crypto.classic.insecure-random": _Profile("other", ("generate",)),
    # Claves de certificados y archivos de claves (certs.py): un certificado sirve para firmar.
    "crypto.pqc.cert-quantum-vulnerable": _Profile("signature", ("sign", "verify")),
    "crypto.pqc.cert-weak-key": _Profile("signature", ("sign", "verify")),
}

# Reglas de certs.py que hablan de la clave: entran como algoritmo, igual que en el código.
_CERT_KEY_RULES = {"crypto.pqc.cert-quantum-vulnerable", "crypto.pqc.cert-weak-key"}
# Problemas que existen hoy, sin computadora cuántica.
_BROKEN_RULES = {"crypto.pqc.cert-weak-signature", "crypto.pqc.cert-expired"}
_THREAT_ORDER = ["broken", "shor", "grover", "none"]
_UNKNOWN = _Profile("unknown", ("unknown",))

# Nombre del algoritmo para las reglas de classic.py, que no lo traen en `metadata`.
_CLASSIC_ALGORITHMS = {
    "crypto.classic.weak-hash": "MD5 / SHA-1",
    "crypto.classic.weak-cipher": "DES / 3DES / RC4 / Blowfish",
    "crypto.classic.aes-ecb": "AES-ECB",
    "crypto.classic.rsa-weak-key": "RSA < 2048",
    "crypto.classic.insecure-random": "Random no criptográfico",
    "crypto.classic.tls-insecure": "TLS sin validar",
}

# Lo rompe una computadora cuántica con el algoritmo de Shor.
_SHOR_RULES = {
    "crypto.pqc.rsa-keygen", "crypto.pqc.ec-keygen", "crypto.pqc.ecdsa", "crypto.pqc.eddsa",
    "crypto.pqc.ecdh", "crypto.pqc.dh", "crypto.pqc.dsa-keygen", "crypto.classic.rsa-weak-key",
    "crypto.pqc.cert-quantum-vulnerable", "crypto.pqc.cert-weak-key",
}

# (seguridad clásica en bits, categoría de seguridad cuántica de NIST de 1 a 5).
# Los hashes cuentan por resistencia a colisiones; los cifrados, por Grover.
_SECURITY_LEVELS: dict[str, tuple[int, int]] = {
    "AES-128": (128, 1),
    "AES-192": (192, 3),
    "AES-256": (256, 5),
    "ChaCha20-Poly1305": (256, 5),
    "SHA-256": (128, 2),
    "SHA-384": (192, 4),
    "SHA-512": (256, 5),
    "SHA3-256": (128, 2),
    "SHA3-384": (192, 4),
    "SHA3-512": (256, 5),
    "BLAKE2b": (256, 5),
}


def build_cyclonedx(scan_id: str, repo_url: str, commit_sha: str, findings: dict[str, Finding]) -> dict:
    """CBOM del escaneo: un componente por algoritmo, con cada lugar donde aparece,
    y uno por cada certificado versionado en el repo."""
    by_ref: dict[str, list[tuple[str, Finding]]] = {}
    certificates: dict[str, list[tuple[str, Finding]]] = {}
    for fp, finding in findings.items():
        if finding.engine != "crypto":
            continue
        is_cert_rule = finding.rule_id.startswith("crypto.pqc.cert-")
        if not is_cert_rule or finding.rule_id in _CERT_KEY_RULES:
            by_ref.setdefault(_bom_ref(finding), []).append((fp, finding))
        if is_cert_rule and finding.metadata.get("kind") == "certificate":
            certificates.setdefault(_certificate_ref(finding), []).append((fp, finding))

    components = [_component(ref, usages) for ref, usages in sorted(by_ref.items())]
    components += [_certificate_component(ref, usages) for ref, usages in sorted(certificates.items())]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "Qubitor"}]},
            "component": {
                "type": "application",
                "bom-ref": REPOSITORY_REF,
                "name": _repository_name(repo_url),
                "externalReferences": [{"type": "vcs", "url": repo_url}] if repo_url else [],
            },
            "properties": [
                {"name": "qubitor:scan_id", "value": scan_id},
                {"name": "qubitor:commit_sha", "value": commit_sha},
            ],
        },
        "components": components,
        "dependencies": [{"ref": REPOSITORY_REF, "dependsOn": [c["bom-ref"] for c in components]}],
    }


def algorithm_name(finding: Finding) -> str:
    algorithm = finding.metadata.get("algorithm")
    if isinstance(algorithm, str) and algorithm:
        return algorithm
    return _CLASSIC_ALGORITHMS.get(finding.rule_id, finding.title)


def quantum_threat(rule_id: str) -> str:
    """shor: lo rompe · grover: le baja la seguridad · broken: ya está roto hoy · none."""
    if rule_id in _SHOR_RULES:
        return "shor"
    if rule_id in _BROKEN_RULES:
        return "broken"
    if rule_id == "crypto.pqc.aes-128":
        return "grover"
    if rule_id.startswith("crypto.classic."):
        return "broken"
    return "none"


def _component(ref: str, usages: list[tuple[str, Finding]]) -> dict:
    first = usages[0][1]
    name = algorithm_name(first)
    worst = min((finding.severity for _, finding in usages), key=_SEVERITY_ORDER.index)
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": _crypto_properties(first, name),
        "evidence": {
            "occurrences": [
                {"location": finding.file_path, **({"line": finding.line} if finding.line else {}),
                 "additionalContext": f"{finding.rule_id} · fingerprint {fp}"}
                for fp, finding in sorted(usages, key=lambda u: (u[1].file_path, u[1].line or 0))
            ]
        },
        "properties": [
            {"name": "qubitor:severity", "value": worst.value},
            {"name": "qubitor:quantum-threat", "value": quantum_threat(first.rule_id)},
            *({"name": "qubitor:rule_id", "value": rule} for rule in sorted({f.rule_id for _, f in usages})),
        ],
    }


def _certificate_component(ref: str, usages: list[tuple[str, Finding]]) -> dict:
    """Certificado X.509 versionado en el repo: sujeto, vencimiento y sus problemas."""
    first = usages[0][1]
    metadata = first.metadata
    worst = min((finding.severity for _, finding in usages), key=_SEVERITY_ORDER.index)
    threat = min((quantum_threat(finding.rule_id) for _, finding in usages), key=_THREAT_ORDER.index)
    certificate: dict = {"certificateFormat": "X.509"}
    if metadata.get("subject"):
        certificate["subjectName"] = metadata["subject"]
    if metadata.get("not_after"):
        certificate["notValidAfter"] = metadata["not_after"]
    properties = [
        {"name": "qubitor:severity", "value": worst.value},
        {"name": "qubitor:quantum-threat", "value": threat},
        {"name": "qubitor:key-algorithm", "value": algorithm_name(first)},
        *({"name": "qubitor:rule_id", "value": rule} for rule in sorted({f.rule_id for _, f in usages})),
    ]
    if metadata.get("signature_hash"):
        properties.append({"name": "qubitor:signature-hash", "value": metadata["signature_hash"]})
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": metadata.get("subject") or f"Certificado en {first.file_path}",
        "cryptoProperties": {"assetType": "certificate", "certificateProperties": certificate},
        "evidence": {"occurrences": [
            {"location": first.file_path, **({"line": first.line} if first.line else {})},
        ]},
        "properties": properties,
    }


def _certificate_ref(finding: Finding) -> str:
    place = f"{finding.file_path}-{finding.line or 0}".lower()
    return "crypto/certificate/" + re.sub(r"[^a-z0-9]+", "-", place).strip("-")


def _crypto_properties(finding: Finding, name: str) -> dict:
    if finding.rule_id == "crypto.classic.tls-insecure":
        return {"assetType": "protocol", "protocolProperties": {"type": "tls"}}

    profile = _RULE_PROFILES.get(finding.rule_id, _UNKNOWN)
    algorithm: dict = {
        "primitive": profile.primitive,
        "executionEnvironment": "software-plain-ram",
        "implementationPlatform": "generic",
        "cryptoFunctions": list(profile.functions),
    }
    if profile.mode:
        algorithm["mode"] = profile.mode
    match = re.search(r"-(\d{3})$", name)
    if profile.primitive == "block-cipher" and match:
        algorithm["parameterSetIdentifier"] = match.group(1)

    threat = quantum_threat(finding.rule_id)
    if threat in ("shor", "broken"):
        algorithm["nistQuantumSecurityLevel"] = 0
    elif name in _SECURITY_LEVELS:
        classical, quantum = _SECURITY_LEVELS[name]
        algorithm["classicalSecurityLevel"] = classical
        algorithm["nistQuantumSecurityLevel"] = quantum
    return {"assetType": "algorithm", "algorithmProperties": algorithm}


def _bom_ref(finding: Finding) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", algorithm_name(finding).lower()).strip("-") or "desconocido"
    return f"crypto/algorithm/{slug}"


def _repository_name(repo_url: str) -> str:
    path = urlparse(repo_url).path.strip("/").removesuffix(".git")
    return path or repo_url or "repositorio"
