"""
enrichment/csv_reader.py — Lecteur des traces de flux par application (étape 2).

Lit les flux réseau d'une app et agrège, par IP destination, les statistiques
nécessaires aux étapes suivantes (volume → DoS, nb de ports → port scan, etc.).

Source privilégiée : traces_reseau/flowoid/traceFlowoid/appFlows/<app>.csv
(avec en-tête, contient dstname/rDNS). Repli : traces_reseau/chaingen/<app>.csv
(5-tuple sans en-tête) si appFlows absent.

Garde-fous :
  - on ne lit QUE le CSV de l'app (quelques Ko-centaines de Ko), JAMAIS le fichier
    maître androidflows.csv (705 Mo) ;
  - on ne charge que les colonnes utiles (usecols) ;
  - filtrage des flux SORTANTS (src = device, IP privée 10.x).

Ce module NE fait QUE lire/agréger : pas de résolution ASN, pas de mapping
label-DOT→IP, pas de classification, aucun réseau, aucun LLM.
"""

from __future__ import annotations

import ipaddress
import pathlib
from dataclasses import dataclass, field

import pandas as pd

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_APPFLOWS_DIR = _PROJECT_ROOT / "flowoid-traces-intern" / "traces_reseau" / "flowoid" / "traceFlowoid" / "appFlows"
_CHAINGEN_DIR = _PROJECT_ROOT / "flowoid-traces-intern" / "traces_reseau" / "chaingen"

# Le device (smartphone) émet depuis une IP NON publique. Selon l'app, c'est une
# plage privée RFC1918 (10/8, 172.16/12, 192.168/16) OU du CGNAT opérateur
# (100.64.0.0/10). On détecte donc « device » = IP non routable globalement.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_device(ip_str: str) -> bool:
    """True si l'IP est celle du device (privée RFC1918 ou CGNAT 100.64/10)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip.is_private or ip in _CGNAT

# Colonnes utiles dans appFlows (on ne charge QUE celles-là)
_APPFLOWS_COLS = ["srcaddr", "dstaddr", "dstport", "protocol", "bytes", "packets", "dstname"]
# Colonnes du 5-tuple chaingen (sans en-tête) : ts, src, sport, dst, dport, proto, bytes, packets, start, end
_CHAINGEN_NAMES = ["ts", "srcaddr", "srcport", "dstaddr", "dstport", "protocol",
                   "bytes", "packets", "starttime", "endtime"]


# ---------------------------------------------------------------------------
# Structures de sortie
# ---------------------------------------------------------------------------

@dataclass
class EndpointStats:
    dst_ip: str
    bytes_total: int = 0
    packets_total: int = 0
    nb_flows: int = 0
    ports: set[int] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    dstname: str | None = None     # rDNS si disponible (appFlows)


@dataclass
class AppFlows:
    app: str
    csv_path: pathlib.Path
    source: str                    # "appFlows" | "chaingen"
    csv_size_bytes: int
    n_rows_read: int               # lignes lues (toutes directions)
    n_outbound: int                # flux device→serveur retenus
    endpoints: dict[str, EndpointStats] = field(default_factory=dict)
    port_index: dict[int, set[str]] = field(default_factory=dict)   # port → {ips}
    ip_ports: dict[str, set[int]] = field(default_factory=dict)     # ip → {ports}


# ---------------------------------------------------------------------------
# Résolution du fichier source
# ---------------------------------------------------------------------------

def resolve_csv(app: str) -> tuple[pathlib.Path, str] | None:
    """Retourne (chemin, source) en privilégiant appFlows ; None si rien trouvé."""
    cand = _APPFLOWS_DIR / f"{app}.csv"
    if cand.exists():
        return cand, "appFlows"
    for alt in (_CHAINGEN_DIR / f"{app}.csv", _CHAINGEN_DIR / f"{app}.csv.n"):
        if alt.exists():
            return alt, "chaingen"
    return None


# ---------------------------------------------------------------------------
# Lecture + agrégation
# ---------------------------------------------------------------------------

def _to_int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def read_app(app: str) -> AppFlows | None:
    """Lit le CSV de l'app et agrège les stats par IP destination (flux sortants)."""
    resolved = resolve_csv(app)
    if resolved is None:
        return None
    path, source = resolved

    if source == "appFlows":
        df = pd.read_csv(path, usecols=lambda c: c in _APPFLOWS_COLS,
                         low_memory=False)
    else:  # chaingen : pas d'en-tête, 5-tuple
        df = pd.read_csv(path, header=None, names=_CHAINGEN_NAMES,
                         usecols=["srcaddr", "dstaddr", "dstport", "protocol", "bytes", "packets"],
                         low_memory=False)

    n_rows = len(df)
    result = AppFlows(app=app, csv_path=path, source=source,
                      csv_size_bytes=path.stat().st_size, n_rows_read=n_rows, n_outbound=0)

    has_dstname = "dstname" in df.columns
    for row in df.itertuples(index=False):
        src = str(getattr(row, "srcaddr", "") or "")
        # ── flux SORTANTS uniquement : source = device (privée ou CGNAT) ─────
        if not _is_device(src):
            continue
        dst = str(getattr(row, "dstaddr", "") or "")
        if not dst:
            continue
        result.n_outbound += 1

        ep = result.endpoints.get(dst)
        if ep is None:
            ep = EndpointStats(dst_ip=dst)
            result.endpoints[dst] = ep
        ep.nb_flows += 1
        ep.bytes_total += _to_int(getattr(row, "bytes", 0))
        ep.packets_total += _to_int(getattr(row, "packets", 0))
        port = _to_int(getattr(row, "dstport", 0))
        if port:
            ep.ports.add(port)
        proto = getattr(row, "protocol", None)
        if proto is not None and str(proto).strip():
            ep.protocols.add(str(proto).strip())
        if has_dstname and ep.dstname is None:
            dn = getattr(row, "dstname", None)
            if dn is not None and str(dn).strip() and str(dn) != "nan":
                ep.dstname = str(dn).strip()

    # ── Index port→ips et ip→ports ───────────────────────────────────────────
    for ip, ep in result.endpoints.items():
        result.ip_ports[ip] = set(ep.ports)
        for p in ep.ports:
            result.port_index.setdefault(p, set()).add(ip)

    return result


# ---------------------------------------------------------------------------
# Démo / vérification (aucun réseau, aucun LLM)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    apps = ["disneyland", "dropbox", "faceswitch", "lequipe", "pokemongo", "ratp", "viber"]
    for app in apps:
        r = read_app(app)
        if r is None:
            print(f"❌ {app:<12} : aucun CSV trouvé")
            continue
        print(f"✅ {app:<12} source={r.source:<9} "
              f"fichier={r.csv_path.name} ({r.csv_size_bytes/1024:.0f} Ko)  "
              f"lignes={r.n_rows_read}  sortants={r.n_outbound}  "
              f"IPs_dst={len(r.endpoints)}")
