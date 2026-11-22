"""whitelist/sni_parser.py — Extraction du SNI (nom de domaine) depuis un TLS
ClientHello, et liste de domaines malveillants.

C'est ce que ni le firewall (IP/port) ni la réputation (IP/ASN) ne voient : le
DOMAINE demandé. L'IDS (s2) miroite le paquet au contrôleur, qui parse ici le SNI.

extract_sni(payload) : renvoie le domaine (str) ou None.
is_malicious_domain(name) : le domaine est-il dans la liste malveillante ?
"""
from __future__ import annotations

import json
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JSON = _ROOT / "whitelist" / "malicious_domains.json"


def _load() -> set[str]:
    try:
        return {str(d).lower() for d in json.loads(_JSON.read_text())}
    except Exception:
        return set()


_MAL_DOMAINS = _load()


def is_malicious_domain(name: str | None) -> bool:
    """Domaine (SNI) connu malveillant ? Match exact OU suffixe (sous-domaine)."""
    if not name:
        return False
    n = name.lower().rstrip(".")
    if n in _MAL_DOMAINS:
        return True
    # suffixe : c2.evil.com couvre a.c2.evil.com
    return any(n == d or n.endswith("." + d) for d in _MAL_DOMAINS)


def n_domains() -> int:
    return len(_MAL_DOMAINS)


def extract_sni(payload: bytes) -> str | None:
    """Parse un TLS ClientHello (payload TCP) et renvoie le SNI, ou None.

    Structure : record TLS (type=0x16 handshake) → handshake (type=0x01 ClientHello)
    → version, random(32), session_id, cipher_suites, compression, extensions
    → extension server_name (type=0x0000) → host_name.
    Robuste : renvoie None au moindre doute (pas d'exception qui remonte).
    """
    try:
        p = payload
        if len(p) < 5 or p[0] != 0x16:          # TLS handshake ?
            return None
        # record: [type(1)][version(2)][length(2)]  → handshake commence à 5
        i = 5
        if i + 4 > len(p) or p[i] != 0x01:      # ClientHello ?
            return None
        # handshake: [type(1)][length(3)] → corps à i+4
        i += 4
        i += 2                                   # client_version (2)
        i += 32                                  # random (32)
        if i >= len(p):
            return None
        sid_len = p[i]; i += 1 + sid_len         # session_id
        if i + 2 > len(p):
            return None
        cs_len = int.from_bytes(p[i:i+2], "big"); i += 2 + cs_len   # cipher_suites
        if i >= len(p):
            return None
        comp_len = p[i]; i += 1 + comp_len       # compression_methods
        if i + 2 > len(p):
            return None
        ext_total = int.from_bytes(p[i:i+2], "big"); i += 2         # extensions length
        end = min(len(p), i + ext_total)
        while i + 4 <= end:
            etype = int.from_bytes(p[i:i+2], "big")
            elen = int.from_bytes(p[i+2:i+4], "big")
            i += 4
            if etype == 0x0000:                  # server_name extension
                # [list_len(2)][name_type(1)=0][name_len(2)][name]
                j = i + 2 + 1                     # saute list_len + name_type
                if j + 2 > len(p):
                    return None
                nlen = int.from_bytes(p[j:j+2], "big"); j += 2
                if j + nlen > len(p):
                    return None
                return p[j:j+nlen].decode("ascii", "ignore")
            i += elen
        return None
    except Exception:
        return None
