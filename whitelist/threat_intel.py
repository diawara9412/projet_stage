"""
whitelist/threat_intel.py — Source de RÉPUTATION (threat-intel) pour le niveau 3.

Quand le contrôleur escalade un flux que le /16 ne connaît pas, l'Analyzer doit
l'ENRICHIR. La réputation = est-ce une destination connue malveillante ?
Source réelle : les C2 du Android Mischief Dataset (benchmark/results/mischief_c2.json),
+ quelques plages connues (Tor/known-bad) extensibles. Déterministe, offline.
"""
from __future__ import annotations

import json
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_C2_JSON = _ROOT / "benchmark" / "results" / "mischief_c2.json"
# Base APPRISE (rétroaction) : IP flaguées à l'exécution par VirusTotal / les agents.
# Persistée à part pour ne pas corrompre le dataset Mischief (lecture seule).
_LEARNED_JSON = _ROOT / "whitelist" / "learned_malicious.json"

# Plages connues malveillantes/anonymisantes (extensible). Préfixes /16 ou IP exactes.
_KNOWN_BAD_PREFIXES: set[str] = set()


def _load_c2() -> set[str]:
    try:
        return {c["c2_ip"] for c in json.loads(_C2_JSON.read_text()) if c.get("c2_ip")}
    except Exception:
        return set()


def _load_learned() -> set[str]:
    try:
        return set(json.loads(_LEARNED_JSON.read_text()))
    except Exception:
        return set()


_MALICIOUS_IPS = _load_c2() | _load_learned()


def reputation(ip: str) -> str:
    """Retourne 'malicious' si l'IP est connue malveillante (threat-intel), sinon 'unknown'."""
    if ip in _MALICIOUS_IPS:
        return "malicious"
    if ".".join(ip.split(".")[:2]) in _KNOWN_BAD_PREFIXES:
        return "malicious"
    return "unknown"


def add_malicious(ip: str) -> bool:
    """RÉTROACTION (apprentissage) : ajoute une IP à la base de réputation et la PERSISTE.
    Appelée quand VirusTotal / les agents déclarent une IP malveillante à l'exécution.
    Le contrôleur la bloquera alors DIRECTEMENT ensuite, sans ré-escalade. Idempotente."""
    if not ip or ip in _MALICIOUS_IPS:
        return False
    _MALICIOUS_IPS.add(ip)
    learned = _load_learned()
    learned.add(ip)
    try:
        _LEARNED_JSON.write_text(json.dumps(sorted(learned), indent=1))
    except Exception:
        pass
    return True


def n_known() -> int:
    return len(_MALICIOUS_IPS)
