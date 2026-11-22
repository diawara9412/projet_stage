"""
enrichment/asn_resolver.py — Résolveur IP → (ASN, organisation, trusted, bgp_rank) — étape 3.

OFFLINE-FIRST, dans l'ordre :
  1. CACHE baseline : enrichment/data/asn_cache.json (résolutions MaxMind figées).
  2. MAXMIND        : base GeoLite2-ASN locale (enrichment/data/GeoLite2-ASN.mmdb),
                      lue par la lib `maxminddb`. Hors-ligne, déterministe.
  3. ALLOWLIST      : org connues (Google/Amazon/Akamai/Cloudflare/Microsoft…) → trusted.
  4. RDAP (ipwhois) : repli RÉSEAU, OPT-IN (enable_rdap=True) — remplit asn/org si MaxMind échoue.
  5. BGP Ranking    : réputation RÉSEAU, OPT-IN (enable_bgp=True) — note l'ASN (CIRCL).

Sources RÉSEAU (RDAP, BGP) : OPT-IN, OFF par défaut. Avec les deux flags OFF, le
comportement est STRICTEMENT identique à la baseline MaxMind (invariance garantie).
Leurs réponses sont mises en cache dans un fichier DATÉ SÉPARÉ (net_cache_<date>.json),
JAMAIS dans asn_cache.json → la baseline offline reste pure et reproductible.

Dégradation propre : si une lib/base/serveur manque ou time-out, le résolveur reste
fonctionnel et renvoie source="unavailable" / bgp_rank=None — il n'invente JAMAIS de
valeur, ne contacte le réseau que si le flag correspondant est activé.

Méthodo : MaxMind = baseline reproductible ; MaxMind+RDAP+BGP = VARIANTE évaluée à part.
Tout résultat dérivé du BGP est PRÉLIMINAIRE tant que unsafe_threshold n'est pas calibré.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from datetime import date as _date, datetime, timezone

_DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"
_MMDB_PATH = _DATA_DIR / "GeoLite2-ASN.mmdb"
_CACHE_PATH = _DATA_DIR / "asn_cache.json"            # baseline MaxMind (offline, pur)

# Endpoint BGP Ranking de CIRCL (réputation par ASN). Réseau, opt-in uniquement.
_BGP_RANKING_URL = "https://bgpranking.circl.lu/json/asn"

# Allowlist : sous-chaînes d'org considérées « de confiance » (factuel, ajustable).
_TRUSTED_ORG_KEYWORDS = [
    "google", "amazon", "aws", "akamai", "cloudflare", "microsoft", "azure",
    "apple", "fastly", "facebook", "meta", "netflix", "oracle", "ibm",
]


@dataclass
class AsnResult:
    ip: str
    asn: int | None
    org: str | None
    is_trusted: bool            # org ∈ allowlist
    source: str                 # "cache" | "maxmind" | "rdap" | "unavailable"
    # ── Champs réseau OPT-IN (None si flags off → invariance baseline) ──────
    bgp_rank: float | None = None     # réputation CIRCL de l'ASN (None = non interrogé)
    resolved_at: str | None = None    # horodatage ISO de la résolution réseau (repro)
    bgp_date: str | None = None       # date d'édition BGP demandée à CIRCL (repro)


class AsnResolver:
    """Résolveur IP→ASN/org(+bgp_rank), offline-first, caches baseline+réseau séparés."""

    def __init__(self, enable_rdap: bool = False, enable_bgp: bool = False,
                 edition_date: str | None = None):
        # Sources réseau OPT-IN, OFF par défaut (baseline MaxMind inchangée).
        self.enable_rdap = enable_rdap
        self.enable_bgp = enable_bgp
        # Édition datée (fige une variante réseau reproductible). None → aujourd'hui.
        self.edition_date = edition_date or _date.today().isoformat()
        self._mmdb = None
        self._mmdb_status = "non initialisée"
        self._cache: dict[str, dict] = self._load_cache()       # baseline (asn_cache.json)
        # Cache réseau DATÉ, chargé seulement si une source réseau est active.
        self._net_path = _DATA_DIR / f"net_cache_{self.edition_date}.json"
        self._net_cache: dict[str, dict] = (
            self._load_net_cache() if (enable_rdap or enable_bgp) else {})
        self._open_mmdb()

    # ── Initialisation MaxMind (sans réseau) ────────────────────────────────
    def _open_mmdb(self) -> None:
        try:
            import maxminddb
        except ImportError:
            self._mmdb_status = "lib 'maxminddb' non installée"
            return
        if not _MMDB_PATH.exists():
            self._mmdb_status = f"base absente ({_MMDB_PATH.name})"
            return
        try:
            self._mmdb = maxminddb.open_database(str(_MMDB_PATH))
            self._mmdb_status = "OK"
        except Exception as exc:                # pragma: no cover
            self._mmdb_status = f"ouverture échouée : {exc}"

    @property
    def maxmind_available(self) -> bool:
        return self._mmdb is not None

    @property
    def maxmind_status(self) -> str:
        return self._mmdb_status

    # ── Cache JSON ──────────────────────────────────────────────────────────
    def _load_cache(self) -> dict:
        if _CACHE_PATH.exists():
            try:
                return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def save_cache(self) -> None:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(
            json.dumps(self._cache, indent=2, ensure_ascii=False), encoding="utf-8")

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    # ── Cache réseau DATÉ (RDAP/BGP) — séparé de la baseline, jamais asn_cache.json ──
    def _load_net_cache(self) -> dict:
        if self._net_path.exists():
            try:
                return json.loads(self._net_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def save_net_cache(self) -> None:
        """Persiste le cache réseau daté (no-op si aucune source réseau active)."""
        if not (self.enable_rdap or self.enable_bgp):
            return
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._net_path.write_text(
            json.dumps(self._net_cache, indent=2, ensure_ascii=False), encoding="utf-8")

    @property
    def net_cache_size(self) -> int:
        return len(self._net_cache)

    # ── Allowlist ───────────────────────────────────────────────────────────
    @staticmethod
    def _is_trusted(org: str | None) -> bool:
        if not org:
            return False
        o = org.lower()
        return any(k in o for k in _TRUSTED_ORG_KEYWORDS)

    # ── Repli RDAP (réseau, seulement si enable_rdap) ───────────────────────
    @staticmethod
    def _rdap(ip: str, timeout: float = 5.0) -> tuple[int | None, str | None]:
        """RDAP (successeur de whois) → (asn, org/netname). (None,None) si échec/timeout."""
        try:
            from ipwhois import IPWhois
            # timeout explicite : pas de blocage réseau, échec propre → (None, None)
            r = IPWhois(ip, timeout=timeout).lookup_rdap(depth=0)
            raw_asn = (r.get("asn") or "").split()[0] if r.get("asn") else None
            asn = int(raw_asn) if raw_asn and raw_asn.isdigit() else None
            org = r.get("asn_description") or (r.get("network") or {}).get("name")
            return asn, org
        except Exception:
            return None, None

    # ── BGP Ranking CIRCL (réseau, seulement si enable_bgp) ─────────────────
    @staticmethod
    def _bgp_rank(asn: int, date: str | None = None, timeout: float = 4.0) -> float | None:
        """Note de réputation de l'ASN via CIRCL BGP Ranking. None si échec/timeout.

        POST {asn, date?} → JSON. Le ranking se trouve sous response.ranking.rank
        (schéma API v2). Aucune valeur inventée : tout aléa réseau/format → None.
        """
        try:
            import requests
            payload: dict = {"asn": str(asn)}
            if date:
                payload["date"] = date
            resp = requests.post(_BGP_RANKING_URL, json=payload, timeout=timeout)
            if resp.status_code != 200:
                return None
            data = resp.json()
            # Schéma v2 : {"response": {"ranking": {"rank": <float>, "position": ...}}}
            node = (data.get("response") or {}).get("ranking") or {}
            rank = node.get("rank")
            return float(rank) if rank is not None else None
        except Exception:
            return None

    # ── Résolution principale ───────────────────────────────────────────────
    def resolve(self, ip: str) -> AsnResult:
        asn: int | None = None
        org: str | None = None
        source = "unavailable"
        resolved_at: str | None = None

        # 1) cache baseline (MaxMind figé)
        if ip in self._cache:
            c = self._cache[ip]
            asn, org, source = c.get("asn"), c.get("org"), "cache"
            is_trusted = c.get("is_trusted", False)      # valeur figée (invariance)
        else:
            # 2) MaxMind (offline)
            if self._mmdb is not None:
                try:
                    rec = self._mmdb.get(ip)
                except Exception:
                    rec = None
                if rec:
                    asn = rec.get("autonomous_system_number")
                    org = rec.get("autonomous_system_organization")
                    if asn is not None or org:
                        source = "maxmind"

            # 3) RDAP (réseau, opt-in) — résultats vers le cache réseau DATÉ
            if source == "unavailable" and self.enable_rdap:
                nc = self._net_cache.get(ip)
                if nc is not None:                       # rejoue l'édition figée
                    asn, org, source = nc.get("asn"), nc.get("org"), "rdap"
                    resolved_at = nc.get("resolved_at")
                else:
                    asn, org = self._rdap(ip)
                    if asn is not None or org:
                        source = "rdap"
                        resolved_at = datetime.now(timezone.utc).isoformat()
                        self._net_cache[ip] = {"asn": asn, "org": org,
                                               "source": "rdap", "resolved_at": resolved_at}

            is_trusted = self._is_trusted(org)
            # Cache BASELINE : UNIQUEMENT MaxMind (RDAP/BGP ne polluent jamais asn_cache).
            if source == "maxmind":
                self._cache[ip] = {"asn": asn, "org": org, "is_trusted": is_trusted}

        # 4) BGP Ranking (réseau, opt-in) — note l'ASN, quel que soit l'origine de l'ASN.
        bgp_rank: float | None = None
        bgp_date: str | None = None
        if self.enable_bgp and asn is not None:
            key = f"asn:{asn}@{self.edition_date}"
            nb = self._net_cache.get(key)
            if nb is not None:                           # rejoue l'édition figée
                bgp_rank = nb.get("bgp_rank")
                bgp_date = nb.get("bgp_date")
                resolved_at = resolved_at or nb.get("resolved_at")
            else:
                bgp_rank = self._bgp_rank(asn, date=self.edition_date)
                bgp_date = self.edition_date
                ts = datetime.now(timezone.utc).isoformat()
                resolved_at = resolved_at or ts
                self._net_cache[key] = {"bgp_rank": bgp_rank, "bgp_date": bgp_date,
                                        "resolved_at": ts}

        return AsnResult(ip, asn, org, is_trusted, source,
                         bgp_rank=bgp_rank, resolved_at=resolved_at, bgp_date=bgp_date)

    def resolve_many(self, ips) -> dict[str, AsnResult]:
        return {ip: self.resolve(ip) for ip in ips}


# ---------------------------------------------------------------------------
# Démo / vérification (offline par défaut, aucun réseau, aucun LLM)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    r = AsnResolver()  # RDAP désactivé
    print(f"MaxMind : {'disponible' if r.maxmind_available else 'INDISPONIBLE'} "
          f"({r.maxmind_status})")
    print(f"Cache   : {r.cache_size} entrée(s)")
    for ip in ["130.211.188.132", "37.58.73.183", "37.187.86.136"]:
        res = r.resolve(ip)
        print(f"  {ip:<18} → ASN={res.asn} org={res.org!r} "
              f"trusted={res.is_trusted} source={res.source}")
    r.save_cache()   # persiste les résolutions réelles dans asn_cache.json
    print(f"Cache écrit : {r.cache_size} entrée(s) → {_CACHE_PATH.name}")
