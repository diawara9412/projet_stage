"""
enrichment/json_builder.py — Assembleur JSON (étape 6).

Combine les 4 modules (dot_parser + csv_reader + asn_resolver + classifier) pour
produire un automate au format EXACT lu par _analyze_deterministic, SANS modifier
le pipeline. Chaque destination (IP) devient une transition.

Mapping catégorie → champs JSON (plan §2) — en garantissant qu'une destination est
SOIT légitime (reputation∈{trusted,neutral}, score<4, flags []) SOIT suspecte
(reputation hors allow-list, score≥4 et/ou flags) ; jamais les deux (sinon le
pipeline générerait ALLOW + BLOCK → conflit) :

  safe       → reputation = trusted/neutral (réelle) | unknown ; flags [] ; score 0-3
  unsafe     → reputation = untrusted ; flags [data_exfiltration] ; score ≥5
  dos        → reputation = suspicious ; flags [syn_flood]   ; score ≥4
  port_scan  → reputation = suspicious ; flags [port_scan]   ; score ≥4
  worm       → reputation = suspicious ; flags []            ; score ≥4  (BLOCK générique)
  botnet     → reputation = untrusted ; flags [beaconing]    ; score ≥6

La réputation ASN réelle (org/asn) est conservée dans service.asn / service.name /
suspicion.notes pour la traçabilité ; service.reputation encode la décision chaîne.

Sur automates PORT : worm/botnet désactivés (limite actée à l'étape 4).
Aucun LLM, aucun réseau (MaxMind local).
"""

from __future__ import annotations

import json
import pathlib
import re
from datetime import datetime, timezone

from enrichment.dot_parser import parse_dot_file
from enrichment.csv_reader import read_app
from enrichment.asn_resolver import AsnResolver
from enrichment.classifier import (
    DEFAULT_THRESHOLDS, classify, reputation_state,
)

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Mapping catégorie → (reputation_chaîne, flags, score_plancher)
# monitored : reputation hors {trusted,neutral} (pas d'ALLOW), flag monitored
# (→ IDS LOW + IPS ALERT_ONLY), score 2 (<4 → pas de BLOCK, cf. skip dans chain_tools).
_CAT_MAP = {
    "monitored": ("monitored", ["monitored"],         2),
    "unsafe":    ("untrusted",  ["data_exfiltration"], 5),
    "dos":       ("suspicious", ["syn_flood"],         4),
    "port_scan": ("suspicious", ["port_scan"],         4),
    "worm":      ("suspicious", [],                    4),
    "botnet":    ("untrusted",  ["beaconing"],         6),
}


# ---------------------------------------------------------------------------
# Jointure self-loop DOT ↔ IP
# ---------------------------------------------------------------------------

def _shared_token(a: str, b: str) -> bool:
    ta = {w for w in re.split(r"[^a-z0-9]+", a) if len(w) >= 4}
    tb = {w for w in re.split(r"[^a-z0-9]+", b) if len(w) >= 4}
    return bool(ta & tb)


def _self_loop_for(graph, ep, org: str | None) -> float:
    """Self-loop attribuable à une IP : par org (ORG) ou par port (PORT)."""
    if graph.label_type == "ORG":
        if not org:
            return 0.0
        o = org.lower()
        best = 0.0
        for n in graph.destination_nodes():
            lab = n.label.lower()
            if o in lab or lab in o or _shared_token(o, lab):
                best = max(best, graph.self_loops[n.node_id])
        return best
    if graph.label_type == "PORT":
        labels = {n.label.strip(): graph.self_loops[n.node_id] for n in graph.destination_nodes()}
        return max([labels.get(str(p), 0.0) for p in ep.ports] or [0.0])
    return 0.0


# ---------------------------------------------------------------------------
# Assemblage
# ---------------------------------------------------------------------------

def build_automate_json(app: str, resolver: AsnResolver | None = None,
                        thresholds: dict | None = None,
                        enable_rdap: bool = False, enable_bgp: bool = False,
                        edition_date: str | None = None) -> dict:
    """Construit le dict JSON enrichi pour une app (format _analyze_deterministic).

    Sources réseau OPT-IN : si ``resolver`` est None, on en crée un avec les flags
    fournis (off par défaut → baseline MaxMind, sortie identique à avant). Si un
    ``resolver`` est passé, il est utilisé tel quel (ses propres flags font foi).
    """
    thr = thresholds or DEFAULT_THRESHOLDS
    resolver = resolver or AsnResolver(enable_rdap=enable_rdap, enable_bgp=enable_bgp,
                                       edition_date=edition_date)
    bgp_on = getattr(resolver, "enable_bgp", False)
    graph = parse_dot_file(_PROJECT_ROOT / "automates" / f"{app}.dot")
    flows = read_app(app)
    if flows is None:
        raise FileNotFoundError(f"CSV de flux introuvable pour {app}")

    # ── États : repris des nœuds DOT (le pipeline n'en lit que le nombre) ────
    states = [{"id": n.node_id, "name": n.label,
               "type": "control" if n.is_special else "destination"}
              for n in graph.nodes.values()]

    transitions = []
    counts: dict[str, int] = {}
    for idx, (ip, ep) in enumerate(sorted(flows.endpoints.items()), start=1):
        res = resolver.resolve(ip)
        # Variante BGP (opt-in) : on passe le seuil ; sinon None → réputation baseline.
        rep = reputation_state(res, unsafe_threshold=(thr.get("unsafe_threshold") if bgp_on else None))
        sl = _self_loop_for(graph, ep, res.org)
        c = classify(dst_ip=ip, bytes_total=ep.bytes_total, distinct_ports=len(ep.ports),
                     self_loop=sl, reputation=rep, label_type=graph.label_type,
                     packets_total=ep.packets_total, nb_flows=ep.nb_flows, thresholds=thr)
        counts[c.primary] = counts.get(c.primary, 0) + 1

        # ── Décision chaîne : reputation + flags + score selon la catégorie ──
        if c.primary == "safe":
            rep_json = rep if rep in ("trusted", "neutral") else "unknown"
            flags: list[str] = []
            score = min(c.score, 3)
        else:
            rep_json, flags, floor = _CAT_MAP[c.primary]
            score = max(c.score, floor)

        port = sorted(ep.ports)[0] if ep.ports else None
        proto = sorted(ep.protocols)[0] if ep.protocols else "TCP"

        # ── Palier B : métriques article (informationnelles) + longueur du limit IDS.
        cor = c.evidence["corroboration"]
        # deploy_limit(a, n) : pour dos/port_scan, n = count(a) (= nb_flows) — fidèle à
        # l'IDS de l'article, sans toucher la classification (None pour les autres cat.).
        ids_limit = cor["count_a"] if c.primary in ("dos", "port_scan") else None

        transitions.append({
            "id": f"t{idx:02d}",
            "from": "INITIAL",
            "to": (res.org or ep.dstname or ip),
            "label": f"{c.primary} → {res.org or ip}",
            "network_call": {
                "ip": ip, "port": port, "protocol": proto,
                "hostname": ep.dstname,
            },
            "service": {
                "name": res.org or ep.dstname or ip,
                "type": "unknown",
                "reputation": rep_json,
                "asn": (f"AS{res.asn}" if res.asn else None),
                "asn_org": res.org,
            },
            "suspicion": {
                "score": score,
                "flags": flags,
                "notes": (f"catégorie={c.primary}; rep_asn={rep}; self_loop={round(sl,3)}; "
                          f"bytes={ep.bytes_total}; ports={len(ep.ports)}; "
                          f"flux={ep.nb_flows}; tier={c.defense_tier}"),
            },
            "behavior": {
                "probability": round(sl, 3) if sl > 0 else 1.0,
            },
            # ── Palier B : métriques article exposées en INFORMATION (corroborantes).
            #    N'influencent PAS la catégorie ; ids_limit_n = longueur n du limit IDS.
            "metrics": {
                "count_a": cor["count_a"],          # count(a) = nb de flux vers l'IP
                "avg_size": cor["avg_size"],        # avg_size = paquets moyens / flux
                "ip_limit_met": cor["ip_limit_met"],
                "min_size_met": cor["min_size_met"],
                "ids_limit_n": ids_limit,           # n du deploy_limit(a, n) (dos/port_scan)
            },
        })

        # Variante BGP (opt-in) : champ AJOUTÉ uniquement si BGP actif → avec BGP off,
        # le JSON reste byte-identique à la baseline (invariance).
        if bgp_on:
            transitions[-1]["service"]["bgp_rank"] = res.bgp_rank
            transitions[-1]["service"]["resolved_at"] = res.resolved_at

    return {
        "automate_id": app,
        "app_name": app,
        "app_version": "enrichment-v1",
        "platform": "android",
        "description": f"Automate enrichi depuis traces flowoid ({app})",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "states": states,
        "transitions": transitions,
        "metadata": {
            "source": "enrichment (dot+csv+maxmind+classifier)",
            "dot_label_type": graph.label_type,
            "csv_source": flows.source,
            "asn_db_available": resolver.maxmind_available,
            "category_counts": counts,
            "thresholds": {k: thr[k] for k in ("attack_limit", "port_scan_limit", "tau_dos")},
            "thresholds_corroborating": {k: thr.get(k) for k in ("ip_limit", "min_size")},
            "thresholds_note": ("PROVISOIRES — choix méthodologique, ajustables. "
                                "ip_limit/min_size = signaux CORROBORANTS (Palier B), "
                                "informationnels : sans effet sur la catégorie."),
        },
    }


# ---------------------------------------------------------------------------
# Démo : ratp uniquement (ORG, contient 1 worm)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    app = sys.argv[1] if len(sys.argv) > 1 else "ratp"
    js = build_automate_json(app)
    print(json.dumps(js, indent=2, ensure_ascii=False))
