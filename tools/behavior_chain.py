"""tools/behavior_chain.py — du COMPORTEMENT à la chaîne de sécurité.

Deux productions à partir du profil comportemental (cf. behavior_traces) :

1. ``brief(profil)``  — la description du comportement **donnée aux agents**.
   C'est l'entrée du raisonnement : quels services, quelles boucles, à quelle
   cadence, quels enchaînements rares. Pas une liste d'adresses à recopier.

2. ``reference_chain(profil)`` — la chaîne **attendue**, dérivée du comportement
   de façon déterministe. Elle sert de VÉRITÉ DE RÉFÉRENCE pour mesurer la
   fidélité des chaînes produites par les différents modèles.

Règles de traduction comportement → politique (modèle liste blanche) :
  · service observé                  → ALLOW (port/plage + protocole)
  · service impliqué dans un
    enchaînement RARE                → ALLOW_AND_INSPECT (surveillance IDS)
  · boucle normale + cadence mesurée → seuil de beaconing calibré sur l'app
  · tout service absent du profil    → refusé par défaut (déviation)
"""
from __future__ import annotations

import json

from tools.behavior_traces import enrich


def _svc_ports(svc: dict) -> str:
    sp = svc["spec"]
    if sp["kind"] == "exact":
        return str(sp["port"])
    if sp["kind"] == "prefix":
        n = 5 - sp["ndigits"]
        return f"{sp['prefix']}xxxx"[: sp["ndigits"] + max(n, 0)] + f" (plage {sp['prefix']}…)"
    return sp.get("label", "*")


def brief(prof: dict, max_ip: int = 5) -> str:
    """Description du comportement destinée aux agents (entrée du raisonnement)."""
    L = [f"COMPORTEMENT RÉSEAU OBSERVÉ — application « {prof['app_name']} »",
         f"(automate du laboratoire : {prof['stats']['n_services']} services, "
         f"{prof['stats']['n_transitions']} enchaînements, "
         f"{prof['stats']['n_loops']} boucles, {prof['stats']['n_rare']} enchaînements rares)",
         "", "SERVICES UTILISÉS (chacun doit être autorisé) :"]
    for s in prof["services"]:
        if not s.get("destinations"):
            L.append(f"  · {s['label']:<9} — aucun flux observé dans les traces")
            continue
        p = s.get("periodicity", {})
        cad = (f", cadence médiane {p['median_interval_s']} s (cv={p['cv']})"
               if p.get("median_interval_s") else "")
        L.append(f"  · {s['label']:<9} {'/'.join(s['protocols']) or '?':<8} "
                 f"{s['n_destinations']} adresses, {s['total_flows']} flux, "
                 f"{s['total_bytes']} octets{cad}")
        for d in s["destinations"][:max_ip]:
            L.append(f"        {d['ip']}  ({d['flows']} flux)")
        if s["n_destinations"] > max_ip:
            L.append(f"        … et {s['n_destinations'] - max_ip} autres adresses")
    if prof["loops"]:
        L += ["", "BOUCLES (l'application reste sur le même service — comportement NORMAL) :"]
        for l in prof["loops"]:
            svc = next((x for x in prof["services"] if x["label"] == l["service"]), {})
            p = svc.get("periodicity", {}) or {}
            cal = (f" — cadence normale {p['median_interval_s']} s"
                   if p.get("median_interval_s") else "")
            L.append(f"  · {l['service']} : P={l['probability']:.3f}{cal}")
    if prof["rare_transitions"]:
        L += ["", "ENCHAÎNEMENTS RARES (à surveiller, pas à bloquer) :"]
        for t in prof["rare_transitions"]:
            L.append(f"  · {t['from']} → {t['to']} : P={t['probability']:.4f}")
    L += ["", "Tout service absent de ce comportement doit être refusé (déviation)."]
    return "\n".join(L)


def reference_chain(prof: dict) -> dict:
    """Chaîne ATTENDUE, dérivée du comportement — vérité de référence."""
    rare_svcs = {t["from"] for t in prof["rare_transitions"]} | \
                {t["to"] for t in prof["rare_transitions"]}
    fw, ids = [], []
    for s in prof["services"]:
        if not s.get("destinations"):
            continue
        watched = s["label"] in rare_svcs or s.get("orphan", False)
        for proto in (s["protocols"] or ["TCP"]):
            fw.append({"service": s["label"], "spec": s["spec"], "protocol": proto,
                       "action": "ALLOW_AND_INSPECT" if watched else "ALLOW",
                       "n_destinations": s["n_destinations"],
                       "destinations": [d["ip"] for d in s["destinations"]]})
        p = s.get("periodicity", {}) or {}
        if watched or p.get("median_interval_s"):
            ids.append({"service": s["label"],
                        "reason": "propriétaire non vérifié" if s.get("orphan")
                                  else "enchaînement rare" if watched else "boucle normale",
                        "expected_interval_s": p.get("median_interval_s"),
                        "expected_cv": p.get("cv"),
                        "beaconing_threshold_s": p.get("median_interval_s")})
    return {"app": prof["app_name"], "model": "liste blanche comportementale",
            "default_action": "DENY",
            "firewall_rules": fw, "ids_signatures": ids,
            "stats": {"n_allow": sum(1 for r in fw if r["action"] == "ALLOW"),
                      "n_inspect": sum(1 for r in fw if r["action"] == "ALLOW_AND_INSPECT"),
                      "n_signatures": len(ids)}}


if __name__ == "__main__":
    import sys
    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    prof = enrich(app)
    print(brief(prof))
    print("\n" + "=" * 70)
    print("CHAÎNE DE RÉFÉRENCE (attendue) :")
    print(json.dumps(reference_chain(prof)["stats"], indent=2, ensure_ascii=False))
    for r in reference_chain(prof)["firewall_rules"]:
        print(f"  {r['action']:<18} service {r['service']:<9} {r['protocol']:<5} "
              f"({r['n_destinations']} adresses)")
