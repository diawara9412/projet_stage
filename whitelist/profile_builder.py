"""
whitelist/profile_builder.py — Modèle LISTE BLANCHE COMPORTEMENTALE (default-deny).

Chemin PROPRE et MINIMAL, indépendant de l'ancien modèle (catégorisation, A/B,
enrich_b) : on n'utilise QUE l'automate + le CSV d'une app pour extraire son PROFIL
= l'ensemble des destinations légitimes (IP, port, protocole). PAS de catégorie, PAS
de score, PAS d'ASN/RDAP dans le chemin critique.

À partir du profil :
  - règles ALLOW = un flow par (IP, port, proto) → forward (NORMAL) ;
  - enforcement DEFAULT-DENY = tout ce qui n'est pas dans le profil est droppé
    (sur le switch : fail-mode=secure + table-miss implicite ; on ajoute en plus
    un flow drop prio 0 pour disposer d'un COMPTEUR de paquets bloqués).

Ne modifie rien de l'existant. Réutilise seulement enrichment.csv_reader.read_app
(lecteur CSV générique — pas de la catégorisation) pour lire les flux bruts.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from enrichment.csv_reader import read_app

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PROFILES_DIR = _ROOT / "profiles"


def _norm_proto(proto: str | None) -> str:
    """Normalise un protocole en 'tcp' | 'udp' (défaut tcp)."""
    p = (str(proto) if proto is not None else "").strip().upper()
    if p in ("UDP", "17"):
        return "udp"
    return "tcp"  # TCP/HTTP/HTTPS/6/inconnu → tcp


@dataclass
class Profile:
    app: str
    triplets: list[tuple[str, int | None, str]] = field(default_factory=list)  # (ip, port, proto)

    @property
    def ips(self) -> set[str]:
        return {t[0] for t in self.triplets}

    @property
    def triplet_set(self) -> set[tuple[str, int | None, str]]:
        return set(self.triplets)

    @property
    def n_ips(self) -> int:
        return len(self.ips)

    @property
    def n_rules(self) -> int:
        return len(self.triplets)


def build_profile(app: str) -> Profile:
    """Construit le profil (IP, port, proto) d'une app depuis son CSV de flux.

    Déterministe, sans LLM/ASN. Une IP avec plusieurs couples (port, proto) produit
    plusieurs triplets → plusieurs règles ALLOW (d'où n_rules ≥ n_ips)."""
    flows = read_app(app)
    if flows is None:
        raise FileNotFoundError(f"CSV de flux introuvable pour '{app}'")
    triplets: set[tuple[str, int | None, str]] = set()
    for ip, ep in flows.endpoints.items():
        ports = ep.ports or {None}
        protos = ep.protocols or {"TCP"}
        for port in ports:
            for proto in protos:
                triplets.add((ip, int(port) if port is not None else None, _norm_proto(proto)))
    return Profile(app=app, triplets=sorted(triplets, key=lambda t: (t[0], t[1] or 0, t[2])))


def allow_flows(profile: Profile, priority: int = 100) -> list[str]:
    """Traduit le profil en flows ovs-ofctl ALLOW (actions=NORMAL).

    Un flow par triplet : match ipv4_dst (+ ip_proto + tp_dst). Si port absent,
    on matche seulement ip + proto.
    """
    flows: list[str] = []
    for ip, port, proto in profile.triplets:
        parts = [f"priority={priority}", "ip", f"nw_dst={ip}", proto]
        if port is not None:
            parts.append(f"tp_dst={port}")
        parts.append("actions=NORMAL")
        flows.append(",".join(parts))
    return flows


def packet_passes(profile: Profile, ip: str, port: int | None, proto: str) -> bool:
    """Sémantique du switch : un paquet (ip,port,proto) PASSE ssi un ALLOW exact
    existe (même ipv4_dst + ip_proto + tp_dst). Sinon DROP (default-deny)."""
    return (ip, port, _norm_proto(proto)) in profile.triplet_set


def save_profile(profile: Profile) -> pathlib.Path:
    """Sauvegarde le profil (JSON portable) dans profiles/<app>_profile.json."""
    _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    out = _PROFILES_DIR / f"{profile.app}_profile.json"
    out.write_text(json.dumps({
        "app": profile.app,
        "n_ips": profile.n_ips,
        "n_rules": profile.n_rules,
        "triplets": [{"ip": ip, "port": port, "proto": proto}
                     for ip, port, proto in profile.triplets],
    }, indent=2), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Prédiction LOGIQUE (sans Mininet/sudo) — valide profile + sémantique de match.
# Le vrai test data-plane (whitelist/anomaly_test.py) doit confirmer ces nombres.
# ---------------------------------------------------------------------------

def predict(profile_app: str, replay_app: str) -> dict:
    """Prédit, par IP, ce qui passerait/serait bloqué si on déploie le profil
    `profile_app` (default-deny) et qu'on rejoue le trafic de `replay_app`."""
    prof = build_profile(profile_app)
    rep = build_profile(replay_app)
    rep_ips = sorted(rep.ips)
    passed = [ip for ip in rep_ips
              if any(packet_passes(prof, ip, port, proto)
                     for (i2, port, proto) in rep.triplets if i2 == ip)]
    blocked = [ip for ip in rep_ips if ip not in passed]
    return {
        "profile_app": profile_app, "replay_app": replay_app,
        "profile_n_ips": prof.n_ips, "profile_n_rules": prof.n_rules,
        "replay_n_ips": rep.n_ips,
        "passed": passed, "blocked": blocked,
        "accept_rate": round(len(passed) / len(rep_ips), 4) if rep_ips else 0.0,
        "block_rate": round(len(blocked) / len(rep_ips), 4) if rep_ips else 0.0,
        "overlap_ips": sorted(prof.ips & rep.ips),
    }


if __name__ == "__main__":
    import sys
    for app in (sys.argv[1:] or ["lequipe", "viber"]):
        p = build_profile(app)
        out = save_profile(p)
        print(f"{app:<10} : {p.n_ips} IP, {p.n_rules} règles ALLOW → {out.name}")
