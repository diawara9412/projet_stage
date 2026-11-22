"""Outil VirusTotal partagé (IP + domaine) avec cache — utilisé en proactif ET réactif.

VirusTotal couvre à la fois les adresses IP (`/ip_addresses/{ip}`) et les domaines
(`/domains/{domain}`). On met les réponses en cache pour éviter les requêtes répétées
(et respecter la limite gratuite de 4 requêtes/min). Robuste : sans clé ou en cas
d'erreur, renvoie 0 (ne bloque jamais le pipeline).
"""
from __future__ import annotations
import os
import json
import pathlib
import time

_ROOT = pathlib.Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except Exception:
    pass

_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
_CACHE_IP = _ROOT / "benchmark" / "vt_cache.json"          # réutilise le cache IP existant
_CACHE_DOM = _ROOT / "whitelist" / "vt_domains_cache.json"


def _load(p: pathlib.Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save(p: pathlib.Path, d: dict) -> None:
    try:
        p.write_text(json.dumps(d))
    except Exception:
        pass


_ip_cache = _load(_CACHE_IP)
_dom_cache = _load(_CACHE_DOM)


def _query(kind: str, value: str) -> dict | None:
    """kind = 'ip_addresses' | 'domains'. Renvoie {malicious, suspicious} ou None si échec."""
    if not _KEY:
        return None
    try:
        import requests
        r = requests.get(f"https://www.virustotal.com/api/v3/{kind}/{value}",
                         headers={"x-apikey": _KEY}, timeout=20)
        if r.status_code == 429:                    # rate limit
            time.sleep(20)
            r = requests.get(f"https://www.virustotal.com/api/v3/{kind}/{value}",
                             headers={"x-apikey": _KEY}, timeout=20)
        st = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0)}
    except Exception:
        return None


def check_ip(ip: str) -> dict:
    """Réputation VirusTotal d'une IP : {malicious, suspicious}. Mise en cache."""
    if ip in _ip_cache:
        c = _ip_cache[ip]
        return {"malicious": c.get("malicious", 0), "suspicious": c.get("suspicious", 0)}
    st = _query("ip_addresses", ip)
    if st is not None:
        _ip_cache[ip] = st
        _save(_CACHE_IP, _ip_cache)
    return st or {"malicious": 0, "suspicious": 0}


def check_domain(domain: str) -> dict:
    """Réputation VirusTotal d'un domaine : {malicious, suspicious}. Mise en cache."""
    if domain in _dom_cache:
        return _dom_cache[domain]
    st = _query("domains", domain)
    if st is not None:
        _dom_cache[domain] = st
        _save(_CACHE_DOM, _dom_cache)
    return st or {"malicious": 0, "suspicious": 0}


def is_malicious_ip(ip: str, threshold: int = 1) -> bool:
    """Vrai si au moins `threshold` moteurs classent l'IP comme malveillante."""
    return check_ip(ip).get("malicious", 0) >= threshold


def is_malicious_domain(domain: str, threshold: int = 1) -> bool:
    """Vrai si au moins `threshold` moteurs classent le domaine comme malveillant."""
    return check_domain(domain).get("malicious", 0) >= threshold


def available() -> bool:
    """Vrai si une clé VirusTotal est configurée."""
    return bool(_KEY)
