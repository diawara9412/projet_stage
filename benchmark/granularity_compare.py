#!/usr/bin/env python3
"""
benchmark/granularity_compare.py — ÉTAPE (A) : décision par DOMAINE + rejeu comparatif.

Pour un profil d'app déployé (connu-bon), on rejoue le trafic d'autres apps et on compare,
SUR LES MÊMES IP, ce que déciderait chaque granularité de critère « même que le profil ? » :
    IP exacte  |  préfixe /16  |  ASN/org  |  DOMAINE (rDNS → domaine enregistré)
→ taux EXTEND (jugé légitime) vs BLOCK.

Déterministe, OFFLINE, sans LLM, sans quota. La clé DOMAINE remplace la clé « org » :
elle discrimine quand le rDNS est spécifique (dropbox → *.dropbox.com) mais ÉCHOUE sur le
rDNS générique du cloud (viber → ec2-*.amazonaws.com) — c'est ce qui motive l'étape (B).

Honnêteté : peu d'apps → ce sont des TENDANCES sur ces données, pas des taux universels.

Usage : python3 benchmark/granularity_compare.py
"""
from __future__ import annotations
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from enrichment.csv_reader import read_app

# Domaines de fournisseurs cloud/hébergeurs = GÉNÉRIQUES (ne discriminent pas une app).
_GENERIC_DOMAINS = {
    "amazonaws.com", "compute-1.amazonaws.com", "amazon.com", "akamaitechnologies.com",
    "googleusercontent.com", "1e100.net", "poneytelecom.eu", "ovh.net", "softlayer.com",
    "your-server.de", "rev.poneytelecom.eu", "members.linode.com", "linode.com",
}
_TWO_LEVEL_TLD = {"co.uk", "com.br", "co.jp", "org.uk", "ac.uk", "com.au", "co.in"}


def is_ip(s: str) -> bool:
    return bool(re.fullmatch(r"[\d.]+", s or ""))


def reg_domain(host: str | None) -> str | None:
    """Domaine enregistré depuis un rDNS : api-6a.v.dropbox.com → dropbox.com."""
    if not host:
        return None
    h = host.strip().lower().rstrip(".")
    if not h or is_ip(h):
        return None
    labels = h.split(".")
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_TLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def prefix16(ip: str) -> str:
    return ".".join(ip.split(".")[:2])


# ── Résolution ASN (MaxMind local), avec cache ──────────────────────────────
_ASN_CACHE: dict[str, int | None] = {}
try:
    from enrichment.asn_resolver import AsnResolver
    _RES = AsnResolver()
    _ASN_OK = True
except Exception as _e:  # pragma: no cover
    _ASN_OK = False
    print(f"⚠️ AsnResolver indispo ({_e}) — colonne ASN ignorée")


def asn(ip: str) -> int | None:
    if not _ASN_OK:
        return None
    if ip not in _ASN_CACHE:
        try:
            _ASN_CACHE[ip] = getattr(_RES.resolve(ip), "asn", None)
        except Exception:
            _ASN_CACHE[ip] = None
    return _ASN_CACHE[ip]


# ── Chargement par app : IP → rDNS (dstname) ────────────────────────────────
def load_app(app: str) -> dict[str, str | None]:
    """Retourne {ip: dstname|None} pour les destinations publiques de l'app."""
    flows = read_app(app)
    if flows is None:
        raise FileNotFoundError(f"trace introuvable pour {app}")
    return {ip: ep.dstname for ip, ep in flows.endpoints.items()}


class Profile:
    def __init__(self, app: str, only_ips: set[str] | None = None):
        self.app = app
        full = load_app(app)
        self.ip2name = {ip: full[ip] for ip in only_ips if ip in full} if only_ips is not None else full
        self.ips = set(self.ip2name)
        self.prefixes = {prefix16(ip) for ip in self.ips}
        self.domains = {d for d in (reg_domain(n) for n in self.ip2name.values()) if d}
        self.specific_domains = self.domains - _GENERIC_DOMAINS
        self.asns = {a for a in (asn(ip) for ip in self.ips) if a is not None}


def extend_rates(profile: Profile, replay: Profile) -> dict:
    """Sur TOUTES les IP de `replay`, taux EXTEND (jugé légitime) par critère."""
    ips = sorted(replay.ips)
    n = len(ips)
    res = {"n": n, "ip": 0, "p16": 0, "asn": 0, "dom": 0, "dom_nodata": 0}
    for ip in ips:
        if ip in profile.ips:
            res["ip"] += 1
        if prefix16(ip) in profile.prefixes:
            res["p16"] += 1
        a = asn(ip)
        if a is not None and a in profile.asns:
            res["asn"] += 1
        d = reg_domain(replay.ip2name.get(ip))
        if d is None:
            res["dom_nodata"] += 1  # pas de rDNS exploitable → BLOCK par défaut
        elif d in profile.domains:
            res["dom"] += 1
    return res


def pct(x: int, n: int) -> str:
    return f"{100*x/n:4.0f}%" if n else "  n/a"


def main() -> int:
    apps = ["dropbox", "viber", "lequipe", "faceswitch"]
    profs = {}
    for a in apps:
        try:
            profs[a] = Profile(a)
        except Exception as e:
            print(f"  {a}: {e}")
    print("=" * 74)
    print("  (A) DÉCISION PAR DOMAINE — qualité du rDNS par app")
    print("=" * 74)
    print(f"  {'app':<11}{'IP dest':>8}{'dom. spécifiques':>18}{'dom. génériques':>17}")
    for a, p in profs.items():
        gen = len(p.domains & _GENERIC_DOMAINS)
        print(f"  {a:<11}{len(p.ips):>8}{len(p.specific_domains):>18}{gen:>17}")
    print("  → un rDNS SPÉCIFIQUE (dropbox=*.dropbox.com) discrimine ; un rDNS GÉNÉRIQUE")
    print("    (viber=ec2-*.amazonaws.com) ne dit que « c'est AWS », comme l'ASN.")

    print("\n" + "=" * 74)
    print("  REJEU COMPARATIF — profil déployé = DROPBOX (rDNS spécifique)")
    print("  taux EXTEND (jugé légitime) sur LES MÊMES IP, par granularité de critère")
    print("=" * 74)
    print(f"  {'rejeu':<11}{'#IP':>5}{'IP exacte':>11}{'/16':>8}{'ASN':>8}{'DOMAINE':>10}")
    for a in ["viber", "lequipe", "faceswitch"]:
        if a not in profs:
            continue
        r = extend_rates(profs["dropbox"], profs[a])
        print(f"  {a:<11}{r['n']:>5}{pct(r['ip'],r['n']):>11}{pct(r['p16'],r['n']):>8}"
              f"{pct(r['asn'],r['n']):>8}{pct(r['dom'],r['n']):>10}")
    print("  Lecture : EXTEND faible = bien BLOQUÉ (anomalie). Le DOMAINE doit donner ~0%")
    print("  d'extension (aucune de ces apps n'est *.dropbox.com) → blocage propre.")

    print("\n" + "=" * 74)
    print("  LIMITE DU DOMAINE — profil déployé = VIBER (rDNS générique AWS)")
    print("=" * 74)
    if "viber" in profs and "lequipe" in profs:
        r = extend_rates(profs["viber"], profs["lequipe"])
        print(f"  rejeu lequipe ({r['n']} IP) :  /16={pct(r['p16'],r['n'])}  "
              f"ASN={pct(r['asn'],r['n'])}  DOMAINE={pct(r['dom'],r['n'])}")
        print(f"  viber.domaines = {sorted(profs['viber'].domains)}")
        print("  → 'amazonaws.com' est dans le profil viber (rDNS générique) → le DOMAINE")
        print("    EXTEND à tort toute IP AWS de lequipe. Le domaine ÉCHOUE ici.")

    print("\n" + "=" * 74)
    print("  DÉRIVE LÉGITIME (hold-out) — profil = MOITIÉ des IP dropbox,")
    print("  rejeu = AUTRE MOITIÉ (de vraies destinations dropbox jamais vues)")
    print("=" * 74)
    drop_ips = sorted(profs["dropbox"].ips)
    half_a, half_b = set(drop_ips[::2]), set(drop_ips[1::2])
    prof_a = Profile("dropbox", only_ips=half_a)
    repl_b = Profile("dropbox", only_ips=half_b)
    r = extend_rates(prof_a, repl_b)
    print(f"  rejeu dropbox-héldout ({r['n']} IP) :  IP exacte={pct(r['ip'],r['n'])}  "
          f"/16={pct(r['p16'],r['n'])}  ASN={pct(r['asn'],r['n'])}  DOMAINE={pct(r['dom'],r['n'])}")
    print("  → ici EXTEND ÉLEVÉ = BON (ce SONT de vraies IP dropbox). L'IP-exacte les")
    print("    RATE (faux blocage) ; le DOMAINE les reconnaît (*.dropbox.com) = dérive OK.")

    print("\n" + "=" * 74)
    print("  ⚠️  HONNÊTETÉ SCIENTIFIQUE")
    print("=" * 74)
    print("  • Échantillon PETIT (4 apps) → ces taux sont des TENDANCES sur CES données,")
    print("    pas des valeurs universelles.")
    print("  • Le DOMAINE discrimine UNIQUEMENT quand le rDNS est spécifique (dropbox).")
    print("    Il échoue sur le rDNS générique du cloud (viber/AWS).")
    print("  • Le rDNS n'est PAS le vrai signal : le discriminant est le DNS FORWARD")
    print("    (api.viber.com) / SNI, ABSENT des traces → c'est l'objet de l'étape (B).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
