import json
import os
import urllib.request

import pytest

from app.engines.base import Finding, Severity
from app.storage.cyclonedx import build_cyclonedx, quantum_threat

URL = "https://github.com/org/repo"


def _hallazgo(rule_id, severity, file_path, line, algorithm=None, engine="crypto", title="Título", **extra):
    metadata = {"algorithm": algorithm} if algorithm else {}
    return Finding(
        engine=engine, rule_id=rule_id, title=title, severity=severity, file_path=file_path,
        line=line, snippet="...", description="...", metadata={**metadata, **extra},
    )


CERT = {"kind": "certificate", "subject": "CN=demo.qubitor.invalid", "not_after": "2036-11-05T21:16:51+00:00",
        "signature_hash": "sha1", "key_size": 1024}


def _cert(rule_id, severity, line=1, **extra):
    return _hallazgo(rule_id, severity, "certs/server.pem", line, "RSA", **{**CERT, **extra})


def _cbom(*hallazgos):
    return build_cyclonedx("scan1", URL, "abc123", {f"fp{i}": h for i, h in enumerate(hallazgos)})


def _componente(cbom, nombre):
    return next(c for c in cbom["components"] if c["name"] == nombre)


def _propiedad(componente, nombre):
    return [p["value"] for p in componente["properties"] if p["name"] == nombre]


def test_cabecera_cyclonedx_con_el_repo_y_el_escaneo():
    cbom = _cbom()

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["serialNumber"].startswith("urn:uuid:")
    assert cbom["metadata"]["component"]["name"] == "org/repo"
    assert {"name": "qubitor:commit_sha", "value": "abc123"} in cbom["metadata"]["properties"]
    assert cbom["components"] == []


def test_un_componente_por_algoritmo_con_cada_lugar_donde_aparece():
    cbom = _cbom(
        _hallazgo("crypto.pqc.rsa-keygen", Severity.MEDIUM, "b.py", 7, "RSA"),
        _hallazgo("crypto.pqc.rsa-keygen", Severity.MEDIUM, "a.py", 3, "RSA"),
        _hallazgo("crypto.pqc.inventory.hash", Severity.INFO, "a.py", 9, "SHA-256"),
    )

    rsa = _componente(cbom, "RSA")
    assert rsa["type"] == "cryptographic-asset"
    assert [(o["location"], o["line"]) for o in rsa["evidence"]["occurrences"]] == [("a.py", 3), ("b.py", 7)]
    assert len(cbom["components"]) == 2
    assert cbom["dependencies"] == [{"ref": "repository", "dependsOn": [c["bom-ref"] for c in cbom["components"]]}]


def test_lo_que_rompe_shor_tiene_seguridad_cuantica_cero():
    cbom = _cbom(_hallazgo("crypto.pqc.ecdh", Severity.MEDIUM, "a.py", 1, "ECDH"))

    ecdh = _componente(cbom, "ECDH")
    algoritmo = ecdh["cryptoProperties"]["algorithmProperties"]
    assert algoritmo["primitive"] == "key-agree"
    assert algoritmo["nistQuantumSecurityLevel"] == 0
    assert _propiedad(ecdh, "qubitor:quantum-threat") == ["shor"]


def test_aes_y_hashes_llevan_su_nivel_clasico_y_cuantico():
    cbom = _cbom(
        _hallazgo("crypto.pqc.aes-128", Severity.LOW, "a.py", 1, "AES-128"),
        _hallazgo("crypto.pqc.inventory.aes", Severity.INFO, "a.py", 2, "AES-256"),
        _hallazgo("crypto.pqc.inventory.hash", Severity.INFO, "a.py", 3, "SHA-384"),
    )

    aes128 = _componente(cbom, "AES-128")["cryptoProperties"]["algorithmProperties"]
    assert (aes128["parameterSetIdentifier"], aes128["classicalSecurityLevel"], aes128["nistQuantumSecurityLevel"]) == ("128", 128, 1)
    aes256 = _componente(cbom, "AES-256")["cryptoProperties"]["algorithmProperties"]
    assert aes256["nistQuantumSecurityLevel"] == 5
    sha384 = _componente(cbom, "SHA-384")["cryptoProperties"]["algorithmProperties"]
    assert (sha384["primitive"], sha384["classicalSecurityLevel"], sha384["nistQuantumSecurityLevel"]) == ("hash", 192, 4)


def test_aes_sin_tamano_no_inventa_niveles():
    cbom = _cbom(_hallazgo("crypto.pqc.inventory.aes", Severity.INFO, "a.py", 1, "AES"))

    algoritmo = _componente(cbom, "AES")["cryptoProperties"]["algorithmProperties"]
    assert "nistQuantumSecurityLevel" not in algoritmo
    assert "parameterSetIdentifier" not in algoritmo


def test_la_criptografia_clasica_rota_entra_con_su_nombre():
    cbom = _cbom(
        _hallazgo("crypto.classic.weak-hash", Severity.HIGH, "a.py", 1),
        _hallazgo("crypto.classic.aes-ecb", Severity.MEDIUM, "a.py", 2),
    )

    md5 = _componente(cbom, "MD5 / SHA-1")
    assert _propiedad(md5, "qubitor:quantum-threat") == ["broken"]
    assert md5["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert _componente(cbom, "AES-ECB")["cryptoProperties"]["algorithmProperties"]["mode"] == "ecb"


def test_tls_sin_validar_es_un_protocolo():
    cbom = _cbom(_hallazgo("crypto.classic.tls-insecure", Severity.HIGH, "a.py", 1))

    assert _componente(cbom, "TLS sin validar")["cryptoProperties"] == {
        "assetType": "protocol", "protocolProperties": {"type": "tls"},
    }


def test_regla_desconocida_usa_el_titulo_y_primitiva_desconocida():
    cbom = _cbom(_hallazgo("crypto.pqc.regla-nueva", Severity.INFO, "a.py", 1, title="Algo nuevo"))

    componente = _componente(cbom, "Algo nuevo")
    assert componente["cryptoProperties"]["algorithmProperties"]["primitive"] == "unknown"
    assert _propiedad(componente, "qubitor:quantum-threat") == ["none"]


def test_la_severidad_del_componente_es_la_peor_de_sus_usos():
    cbom = _cbom(
        _hallazgo("crypto.pqc.rsa-keygen", Severity.MEDIUM, "a.py", 1, "RSA"),
        _hallazgo("crypto.classic.rsa-weak-key", Severity.HIGH, "b.py", 2, "RSA"),
    )

    rsa = _componente(cbom, "RSA")
    assert _propiedad(rsa, "qubitor:severity") == ["high"]
    assert _propiedad(rsa, "qubitor:rule_id") == ["crypto.classic.rsa-weak-key", "crypto.pqc.rsa-keygen"]


def test_deja_afuera_los_hallazgos_de_otros_motores():
    cbom = _cbom(_hallazgo("sca.osv.GHSA-x", Severity.HIGH, "requirements.txt", 1, engine="sca"))
    assert cbom["components"] == []


def test_hallazgo_sin_linea_no_lleva_linea():
    cbom = _cbom(_hallazgo("crypto.pqc.inventory.hash", Severity.INFO, "a.py", None, "SHA-256"))
    assert _componente(cbom, "SHA-256")["evidence"]["occurrences"][0].keys() == {"location", "additionalContext"}


def test_certificado_es_un_componente_con_sujeto_vencimiento_y_problemas():
    cbom = _cbom(
        _cert("crypto.pqc.cert-weak-key", Severity.HIGH),
        _cert("crypto.pqc.cert-weak-signature", Severity.HIGH),
    )

    certificado = next(c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "certificate")
    assert certificado["name"] == "CN=demo.qubitor.invalid"
    assert certificado["cryptoProperties"]["certificateProperties"] == {
        "certificateFormat": "X.509",
        "subjectName": "CN=demo.qubitor.invalid",
        "notValidAfter": "2036-11-05T21:16:51+00:00",
    }
    assert certificado["evidence"]["occurrences"] == [{"location": "certs/server.pem", "line": 1}]
    assert _propiedad(certificado, "qubitor:rule_id") == ["crypto.pqc.cert-weak-key", "crypto.pqc.cert-weak-signature"]
    assert _propiedad(certificado, "qubitor:quantum-threat") == ["broken"]
    assert _propiedad(certificado, "qubitor:signature-hash") == ["sha1"]


def test_la_clave_del_certificado_entra_como_algoritmo_junto_con_el_codigo():
    cbom = _cbom(
        _hallazgo("crypto.pqc.rsa-keygen", Severity.MEDIUM, "app/keys.py", 10, "RSA"),
        _cert("crypto.pqc.cert-weak-key", Severity.HIGH),
        _cert("crypto.pqc.cert-weak-signature", Severity.HIGH),
    )

    rsa = _componente(cbom, "RSA")
    assert [o["location"] for o in rsa["evidence"]["occurrences"]] == ["app/keys.py", "certs/server.pem"]
    assert _propiedad(rsa, "qubitor:severity") == ["high"]
    # La firma SHA-1 es del certificado, no de la clave RSA.
    assert "crypto.pqc.cert-weak-signature" not in _propiedad(rsa, "qubitor:rule_id")


def test_clave_suelta_entra_solo_como_algoritmo():
    cbom = _cbom(_hallazgo("crypto.pqc.cert-quantum-vulnerable", Severity.MEDIUM, "firma.key", 1,
                           "Ed25519", kind="private_key"))

    assert [c["cryptoProperties"]["assetType"] for c in cbom["components"]] == ["algorithm"]
    assert _componente(cbom, "Ed25519")["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0


def test_dos_certificados_en_el_mismo_archivo_son_dos_componentes():
    cbom = _cbom(
        _cert("crypto.pqc.cert-quantum-vulnerable", Severity.MEDIUM, line=1, subject="CN=hoja.invalid"),
        _cert("crypto.pqc.cert-expired", Severity.MEDIUM, line=30, subject="CN=raiz.invalid"),
    )

    nombres = [c["name"] for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "certificate"]
    assert nombres == ["CN=hoja.invalid", "CN=raiz.invalid"]


@pytest.mark.parametrize("rule_id, amenaza", [
    ("crypto.pqc.eddsa", "shor"),
    ("crypto.classic.rsa-weak-key", "shor"),
    ("crypto.pqc.aes-128", "grover"),
    ("crypto.classic.insecure-random", "broken"),
    ("crypto.pqc.inventory.password-hash", "none"),
    ("crypto.pqc.cert-quantum-vulnerable", "shor"),
    ("crypto.pqc.cert-weak-key", "shor"),
    ("crypto.pqc.cert-weak-signature", "broken"),
    ("crypto.pqc.cert-expired", "broken"),
    ("crypto.pqc.cert-expiring", "none"),
])
def test_amenaza_cuantica_por_regla(rule_id, amenaza):
    assert quantum_threat(rule_id) == amenaza


_ESQUEMAS = "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/"


@pytest.fixture(scope="module")
def validador():
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource

    esquemas = {}
    for nombre in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        with urllib.request.urlopen(_ESQUEMAS + nombre, timeout=30) as respuesta:
            esquemas[nombre] = json.load(respuesta)
    registro = Registry().with_resources(
        [(nombre, Resource.from_contents(e)) for nombre, e in esquemas.items()]
        + [(e["$id"], Resource.from_contents(e)) for e in esquemas.values() if "$id" in e]
    )
    return Draft7Validator(esquemas["bom-1.6.schema.json"], registry=registro)


@pytest.mark.skipif(os.environ.get("QUBITOR_TESTS_RED") != "1",
                    reason="baja el esquema oficial de CycloneDX; correr con QUBITOR_TESTS_RED=1")
def test_cumple_el_esquema_oficial_de_cyclonedx_1_6(validador):
    reglas = [
        ("crypto.pqc.rsa-keygen", "RSA"), ("crypto.pqc.ec-keygen", "ECC"), ("crypto.pqc.ecdsa", "ECDSA"),
        ("crypto.pqc.eddsa", "EdDSA"), ("crypto.pqc.ecdh", "ECDH"), ("crypto.pqc.dh", "DH"),
        ("crypto.pqc.dsa-keygen", "DSA"), ("crypto.pqc.aes-128", "AES-128"),
        ("crypto.pqc.inventory.aes", "AES-256"), ("crypto.pqc.inventory.hash", "SHA3-512"),
        ("crypto.pqc.inventory.password-hash", "Argon2"), ("crypto.pqc.inventory.chacha20", "ChaCha20-Poly1305"),
        ("crypto.classic.weak-hash", None), ("crypto.classic.weak-cipher", None), ("crypto.classic.aes-ecb", None),
        ("crypto.classic.rsa-weak-key", None), ("crypto.classic.insecure-random", None),
        ("crypto.classic.tls-insecure", None), ("crypto.pqc.regla-nueva", None),
    ]
    certificados = [
        _cert(rule, Severity.HIGH, line=100)
        for rule in ("crypto.pqc.cert-weak-key", "crypto.pqc.cert-weak-signature", "crypto.pqc.cert-expired")
    ] + [_hallazgo("crypto.pqc.cert-quantum-vulnerable", Severity.MEDIUM, "firma.key", 1, "Ed25519", kind="private_key")]
    cbom = _cbom(*(_hallazgo(r, Severity.MEDIUM, "a.py", i + 1, a) for i, (r, a) in enumerate(reglas)), *certificados)

    assert any(c["cryptoProperties"]["assetType"] == "certificate" for c in cbom["components"])
    assert list(validador.iter_errors(cbom)) == []


@pytest.mark.skipif(os.environ.get("QUBITOR_TESTS_RED") != "1",
                    reason="baja el esquema oficial de CycloneDX; correr con QUBITOR_TESTS_RED=1")
def test_el_validador_rechaza_un_cbom_mal_armado(validador):
    cbom = _cbom(_hallazgo("crypto.pqc.ecdh", Severity.MEDIUM, "a.py", 1, "ECDH"))
    cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] = "banana"

    assert list(validador.iter_errors(cbom)) != []
