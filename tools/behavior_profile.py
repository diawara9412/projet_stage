"""tools/behavior_profile.py — lit un automate COMPORTEMENTAL (.dot du labo)
et en produit un PROFIL exploitable par les agents.

L'automate produit par l'équipe décrit le comportement réseau d'une application :
  - un ÉTAT      = un service contacté (un port : 443, 80, 4244/4, « * »…)
  - une ARÊTE    = un enchaînement observé entre deux services, avec sa PROBABILITÉ
  - une SELF-LOOP = l'application reste sur le même service (comportement dominant)

Contrairement à une simple liste d'adresses IP, ce profil porte le COMPORTEMENT :
quels services, dans quel ordre, à quelle fréquence, et avec quelles boucles.
C'est cette information que les agents utilisent pour générer la chaîne :
  · services présents            → ALLOW
  · enchaînements fréquents      → comportement normal
  · enchaînements RARES          → ALLOW + surveiller (IDS)
  · boucles normales             → calibrent le seuil de beaconing
  · tout enchaînement ABSENT     → déviation (anomalie)
"""
from __future__ import annotations

import json
import pathlib
import re

_NODE = re.compile(r'^\s*(\d+)\s*\[label="([^"]*)"')
_EDGE = re.compile(r'(\d+)\s*->\s*(\d+)\s*\[label="P:([0-9.eE+-]+)"\]')

SPECIAL = {"INITIAL", "TERMINAL"}


def parse_dot(path: str | pathlib.Path) -> dict:
    """Lit le .dot brut → {states: {id: label}, edges: [(src, dst, proba)]}."""
    text = pathlib.Path(path).read_text()
    states: dict[str, str] = {}
    for line in text.splitlines():
        m = _NODE.match(line)
        if m:
            states[m.group(1)] = m.group(2)
    edges = [(s, d, float(p)) for s, d, p in _EDGE.findall(text)]
    return {"states": states, "edges": edges}


def port_spec(label: str) -> dict:
    """Interprète l'étiquette d'un état du comportement.

    Le labo GÉNÉRALISE les ports : « préfixe/n » désigne tous les ports dont les
    n premiers chiffres valent le préfixe (« 798/3 » = 7980–7989, la plage de
    ports dynamiques de l'application). Sinon l'étiquette est un port exact, un
    joker « * », ou une organisation (automates construits par organisation).
    """
    l = label.strip()
    if l == "*":
        return {"kind": "any", "label": l}
    if "/" in l:
        head, n = l.split("/", 1)
        if head.isdigit() and n.strip().isdigit():
            return {"kind": "prefix", "prefix": head, "ndigits": int(n), "label": l}
    if l.isdigit():
        return {"kind": "exact", "port": int(l), "label": l}
    return {"kind": "org", "org": l, "label": l}


def port_matches(spec: dict, port: int) -> bool:
    """Le port observé correspond-il à cet état du comportement ?"""
    if spec["kind"] == "exact":
        return port == spec["port"]
    if spec["kind"] == "prefix":
        return str(port)[: spec["ndigits"]] == spec["prefix"]
    return False


def _port_of(label: str) -> int | None:
    """Port représentatif (pour l'affichage/tri) ; None si joker ou organisation."""
    sp = port_spec(label)
    if sp["kind"] == "exact":
        return sp["port"]
    if sp["kind"] == "prefix":
        return int(sp["prefix"].ljust(5, "0")[:5]) if sp["prefix"].isdigit() else None
    return None


def build_profile(path: str | pathlib.Path, rare_threshold: float = 0.01) -> dict:
    """Construit le profil comportemental complet à partir d'un .dot."""
    path = pathlib.Path(path)
    raw = parse_dot(path)
    st, edges = raw["states"], raw["edges"]
    lab = lambda i: st.get(i, f"?{i}")

    services, loops, transitions, rares, entries = [], [], [], [], []

    for i, l in st.items():
        if l in SPECIAL:
            continue
        sp = port_spec(l)
        services.append({"label": l, "port": _port_of(l), "spec": sp,
                         "wildcard": sp["kind"] == "any"})

    for s, d, p in edges:
        ls, ld = lab(s), lab(d)
        if ls == "INITIAL":                       # point d'entrée du comportement
            entries.append({"service": ld, "probability": p})
            continue
        if ld == "TERMINAL":                      # fin de session : pas une règle
            continue
        item = {"from": ls, "to": ld, "probability": round(p, 6),
                "self_loop": ls == ld, "rare": p < rare_threshold}
        transitions.append(item)
        if item["self_loop"]:
            loops.append({"service": ls, "probability": round(p, 6)})
        if item["rare"]:
            rares.append(item)

    services.sort(key=lambda x: (x["port"] is None, x["port"] or 0))
    return {
        "app_name": path.stem,
        "source": str(path),
        "model": "automate comportemental (labo) — états = services, arêtes = enchaînements",
        "services": services,
        "entry_services": entries,
        "transitions": transitions,
        "loops": sorted(loops, key=lambda x: -x["probability"]),
        "rare_transitions": rares,
        "rare_threshold": rare_threshold,
        "stats": {
            "n_services": len(services),
            "n_transitions": len(transitions),
            "n_loops": len(loops),
            "n_rare": len(rares),
        },
    }


def summary(profile: dict) -> str:
    """Résumé lisible (utile pour le prompt des agents et pour le debug)."""
    s = profile["stats"]
    out = [f"Application « {profile['app_name']} » — comportement réseau observé",
           f"  services : {s['n_services']} · enchaînements : {s['n_transitions']} "
           f"· boucles : {s['n_loops']} · rares : {s['n_rare']}",
           "  Services : " + ", ".join(x["label"] for x in profile["services"])]
    if profile["loops"]:
        out.append("  Boucles (comportement répétitif NORMAL) : " + ", ".join(
            f"{l['service']} (P={l['probability']:.3f})" for l in profile["loops"][:5]))
    if profile["rare_transitions"]:
        out.append("  Enchaînements RARES (à surveiller) : " + ", ".join(
            f"{t['from']}→{t['to']} (P={t['probability']:.4f})"
            for t in profile["rare_transitions"][:5]))
    return "\n".join(out)


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parent.parent / "automates"
    for dot in sorted(root.glob("*.dot")):
        p = build_profile(dot)
        print(summary(p)); print()
