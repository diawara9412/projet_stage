"""
whitelist/make_whitelist_automate.py — Génère l'automate LISTE BLANCHE d'une app.

Modèle : toutes les destinations observées sont LÉGITIMES (comportement normal).
On produit un automate au schéma lu par l'architecture (load_automate /
_analyze_deterministic) où CHAQUE destination est un service légitime UNIQUE
(reputation=trusted, aucun flag, score 0). Ainsi :
  - l'Analyzer extrait le profil légitime (aucune catégorie d'attaque) ;
  - le Firewall génère UNE règle ALLOW par destination (services uniques → pas de
    regroupement par org qui ne garderait qu'une IP) ;
  - IDS/IPS restent dans la chaîne (vides, aucune transition suspecte) ;
  - le Déployeur déploie.

Le fichier est écrit dans automates/<app>_whitelist.json — stockage SÉPARÉ : il
n'écrase JAMAIS les <app>_enriched.json (modèle A) ni les _enriched_b.json (modèle B).
NE touche pas à enrichment/ (réutilise seulement le lecteur CSV via profile_builder).

Usage :
    python3 whitelist/make_whitelist_automate.py lequipe viber
    python3 whitelist/make_whitelist_automate.py          # défaut : lequipe viber
"""

from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from whitelist.profile_builder import build_profile

# Destinations « infra » optionnelles (--with-dns) : le résolveur DNS public.
# Ajoutées comme destinations LÉGITIMES → l'Analyzer/Firewall en font des ALLOW
# (udp/53 ET tcp/53). Aucun hardcode dans le contrôleur.
_INFRA_DNS = [("1.1.1.1", 53, "udp"), ("1.1.1.1", 53, "tcp")]


def build_whitelist_automate(app: str, with_dns: bool = False) -> dict:
    """Construit le dict automate liste blanche (toutes destinations légitimes).

    ``with_dns`` : ajoute les triplets infra DNS (1.1.1.1:53 udp+tcp) pour que la
    chaîne autorise la résolution de noms en mode --default-deny.
    """
    prof = build_profile(app)
    triplets = list(prof.triplets)
    if with_dns:
        triplets += [t for t in _INFRA_DNS if t not in triplets]
    n_ips = len({t[0] for t in triplets})
    transitions = []
    states = [{"id": "INITIAL", "name": "INITIAL", "type": "control"}]
    for i, (ip, port, proto) in enumerate(triplets, start=1):
        # Nom de service UNIQUE par triplet → 1 service légitime → 1 ALLOW chacun.
        svc_name = f"wl-{ip}-{port or 'any'}-{proto}"
        states.append({"id": svc_name, "name": svc_name, "type": "destination"})
        transitions.append({
            "id": f"t{i:03d}",
            "from": "INITIAL",
            "to": svc_name,
            "label": f"legit → {ip}:{port}",
            "network_call": {"ip": ip, "port": port,
                             "protocol": (proto or "tcp").upper()},
            "service": {"name": svc_name, "type": "whitelist", "reputation": "trusted"},
            "suspicion": {"score": 0, "flags": [],
                          "notes": "liste blanche comportementale — destination légitime"},
            "behavior": {"probability": 1.0},
        })
    return {
        "automate_id": f"{app}_whitelist",
        "app_name": f"{app} (whitelist)",
        "app_version": "whitelist-v1",
        "platform": "android",
        "description": f"Profil liste blanche comportementale de {app} "
                       f"({n_ips} destinations, {len(triplets)} triplets"
                       + (", DNS infra inclus" if with_dns else "") + ")",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "states": states,
        "transitions": transitions,
        "metadata": {
            "source": "whitelist (csv → destinations légitimes, sans catégorie/ASN)",
            "model": "behavioral_whitelist",
            "with_dns": with_dns,
            "n_destinations": n_ips,
            "n_triplets": len(triplets),
        },
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Génère un automate liste blanche")
    ap.add_argument("apps", nargs="*", default=["lequipe", "viber"],
                    help="apps (défaut : lequipe viber)")
    ap.add_argument("--with-dns", action="store_true",
                    help="ajoute 1.1.1.1:53 (udp+tcp) en destinations légitimes → ALLOW DNS")
    args = ap.parse_args()
    apps = args.apps or ["lequipe", "viber"]
    out_dir = _ROOT / "automates"
    for app in apps:
        try:
            js = build_whitelist_automate(app, with_dns=args.with_dns)
        except Exception as exc:
            print(f"❌ {app} : {exc}")
            continue
        out = out_dir / f"{app}_whitelist.json"
        out.write_text(json.dumps(js, indent=2, ensure_ascii=False), encoding="utf-8")
        md = js["metadata"]
        print(f"✅ {app:<10} → {out.name}  "
              f"({md['n_destinations']} destinations, {md['n_triplets']} ALLOW attendus"
              + (", DNS inclus" if md.get('with_dns') else "") + ")")
    print("\nDéploie ensuite via TES AGENTS (T3), ex. :")
    print("  python3 architectures/supervisor/run_supervisor_test.py --deploy --automate lequipe_whitelist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
