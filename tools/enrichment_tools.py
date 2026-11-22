"""
tools/enrichment_tools.py — Outils (tool-calling LLM) exposant le pipeline
``enrichment/`` à l'agent Analyzer en CONDITION B.

Contexte expérimental
---------------------
- Condition A : traces brutes → pipeline ``enrichment/`` (hors-ligne) → ``*_enriched.json``
  → l'architecture consomme un JSON déjà annoté (flags/score/réputation).
- Condition B : traces brutes → l'Analyzer fait LUI-MÊME le travail, en APPELANT
  ces outils (vrai ``bind_tools`` : c'est le LLM qui décide des appels).

Honnêteté du périmètre (verrouillé)
-----------------------------------
Les SEULS vrais outils sont des wrappers MINCES autour de ``enrichment/`` :
    load_traces · resolve_asn · classify_destination · reputation
Aucune fonction Tor / known_c2 / dga_domain n'est fabriquée : elles n'existent pas
dans le pipeline réel. MITRE reste de l'enrichissement NARRATIF LLM (pas un outil).

``enrichment/`` n'est PAS modifié : on importe et réutilise tel quel
``parse_dot_file``, ``read_app``, ``AsnResolver``, ``classify``, ``reputation_state``,
et même ``_self_loop_for`` / ``_CAT_MAP`` de ``json_builder`` — de sorte que, à
COUVERTURE PLEINE, la sortie de B-det soit identique à celle de A (même logique).

Conception
----------
Les outils sont fabriqués par une instance ``EnrichmentToolbox`` qui porte le
contexte d'un run (graph DOT + flux CSV + résolveur + résultats accumulés). Cela
évite tout état global partagé entre apps/runs (important pour le benchmark ×3).

Le signal scientifique central — la COUVERTURE — émerge naturellement : seuls les
``classify_destination`` réellement appelés par le LLM peuplent ``self.classified``.
Si le LLM saute des destinations, l'assembleur B-det le verra (couverture < 1).
"""

from __future__ import annotations

import logging
import pathlib

from langchain_core.tools import StructuredTool

from enrichment.dot_parser import parse_dot_file
from enrichment.csv_reader import read_app
from enrichment.asn_resolver import AsnResolver
from enrichment.classifier import DEFAULT_THRESHOLDS, classify, reputation_state
# Réutilisation directe de la logique du pipeline (json_builder NON modifié) :
#   _self_loop_for  : jointure self-loop DOT ↔ IP (par org sur ORG, par port sur PORT)
#   _CAT_MAP        : catégorie → (reputation_chaîne, flags, score_plancher)
from enrichment.json_builder import _self_loop_for, _CAT_MAP

logger = logging.getLogger(__name__)

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


class EnrichmentToolbox:
    """Fabrique d'outils enrichment liés au contexte d'UN run d'analyse.

    Usage::

        box = EnrichmentToolbox(enable_bgp=False)
        llm_with_tools = llm.bind_tools(box.tools())
        ...  # boucle de tool-calling ; les outils écrivent dans box.classified
        transitions = box.assemble_transitions()  # pour B-det
    """

    def __init__(self, thresholds: dict | None = None,
                 enable_rdap: bool = False, enable_bgp: bool = False,
                 edition_date: str | None = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        self.resolver = AsnResolver(enable_rdap=enable_rdap, enable_bgp=enable_bgp,
                                    edition_date=edition_date)
        self._bgp_on = getattr(self.resolver, "enable_bgp", False)

        # Contexte chargé par load_traces
        self.app: str | None = None
        self.graph = None
        self.flows = None
        self._endpoints: dict = {}          # ip -> EndpointStats

        # Résultats accumulés par les outils (signal de couverture)
        self.resolved: dict[str, dict] = {}        # ip -> infos ASN/réputation
        self.classified: dict[str, dict] = {}      # ip -> transition (sans id)
        # Décision compacte par IP (flags/score/catégorie/réputation) — base de la
        # comparaison A vs B au niveau destination (peuplée par classify_destination).
        self.decisions: dict[str, dict] = {}

    # ------------------------------------------------------------------ tools
    def tools(self, include_classify: bool = True) -> list[StructuredTool]:
        """Outils à passer à ``llm.bind_tools(...)``.

        ``include_classify`` :
          - True  (B-det) : expose classify_destination (le déterministe décide).
          - False (B-llm) : NE l'expose PAS → le LLM ne reçoit que les signaux
            bruts (load_traces + resolve_asn + reputation) et doit décider
            lui-même flags/score (ablation honnête : pas de copie du résultat).
        """
        tools = [
            StructuredTool.from_function(
                func=self._load_traces, name="load_traces",
                description=(
                    "Charge les traces réseau BRUTES d'une application (DOT + CSV de flux) "
                    "et liste TOUTES ses destinations (IP) avec leurs statistiques brutes "
                    "(octets, nb de ports distincts, paquets, nb de flux, protocoles, hostname). "
                    "À appeler EN PREMIER. Argument: app (nom court, ex. 'pokemongo')."),
            ),
            StructuredTool.from_function(
                func=self._resolve_asn, name="resolve_asn",
                description=(
                    "Résout une IP destination en ASN / organisation / réputation "
                    "(trusted/untrusted/neutral/unknown) via base ASN hors-ligne. "
                    "Argument: ip (une IP vue dans load_traces)."),
            ),
            StructuredTool.from_function(
                func=self._reputation, name="reputation",
                description=(
                    "Donne l'état de réputation (trusted/untrusted/neutral/unknown) d'une IP "
                    "sans la classer. Utile pour le raisonnement. Argument: ip."),
            ),
        ]
        if include_classify:
            tools.insert(2, StructuredTool.from_function(
                func=self._classify_destination, name="classify_destination",
                description=(
                    "Classe UNE destination en catégorie de sécurité (safe/monitored/dos/"
                    "port_scan/worm/botnet/unsafe) et en déduit ses flags, son score et sa "
                    "décision de chaîne, à partir de ses statistiques et de sa réputation. "
                    "À appeler pour CHAQUE destination listée par load_traces. "
                    "Argument: ip."),
            ))
        return tools

    # --------------------------------------------------------------- internals
    def _load_traces(self, app: str) -> dict:
        """Parse le DOT + lit le CSV de flux ; mémorise le contexte du run."""
        app = (app or "").strip()
        self.app = app
        self.graph = parse_dot_file(_PROJECT_ROOT / "automates" / f"{app}.dot")
        flows = read_app(app)
        if flows is None:
            raise FileNotFoundError(f"CSV de flux introuvable pour '{app}'")
        self.flows = flows
        self._endpoints = dict(flows.endpoints)

        destinations = []
        for ip, ep in sorted(self._endpoints.items()):
            destinations.append({
                "ip": ip,
                "bytes_total": ep.bytes_total,
                "distinct_ports": len(ep.ports),
                "packets_total": ep.packets_total,
                "nb_flows": ep.nb_flows,
                "protocols": sorted(ep.protocols),
                "hostname": ep.dstname,
            })
        return {
            "app": app,
            "dot_label_type": self.graph.label_type,
            "nb_destinations": len(destinations),
            "destinations": destinations,
            "note": ("Appelle resolve_asn puis classify_destination pour CHAQUE IP "
                     "ci-dessus afin de couvrir toutes les destinations."),
        }

    def _resolve_one(self, ip: str) -> dict:
        """Résout l'IP (ASN + réputation + self-loop joint) et mémorise le résultat."""
        res = self.resolver.resolve(ip)
        rep = reputation_state(
            res,
            unsafe_threshold=(self.thresholds.get("unsafe_threshold") if self._bgp_on else None),
        )
        # self-loop joint à l'IP (par org sur ORG, par port sur PORT) : signal
        # worm/botnet, utile au LLM en B-llm. Requiert le contexte load_traces.
        ep = self._endpoints.get(ip)
        sl = _self_loop_for(self.graph, ep, res.org) if (self.graph is not None and ep) else 0.0
        info = {
            "ip": ip,
            "asn": (f"AS{res.asn}" if res.asn else None),
            "org": res.org,
            "is_trusted": res.is_trusted,
            "reputation": rep,
            "self_loop": round(sl, 3),
            "source": res.source,
            "bgp_rank": res.bgp_rank if self._bgp_on else None,
        }
        self.resolved[ip] = info
        return info

    def _resolve_asn(self, ip: str) -> dict:
        return self._resolve_one(ip.strip())

    def _reputation(self, ip: str) -> dict:
        info = self._resolve_one(ip.strip())
        return {"ip": info["ip"], "reputation": info["reputation"],
                "org": info["org"], "asn": info["asn"]}

    def _classify_destination(self, ip: str) -> dict:
        """Enrichit UNE destination (mirroir EXACT du corps de boucle de
        build_automate_json, helpers réutilisés) et mémorise la transition.

        Retourne la transition (sans id) ; l'id ``tNN`` est assigné à
        l'assemblage (par IP triée) pour rester comparable à la Condition A.
        """
        ip = ip.strip()
        ep = self._endpoints.get(ip)
        if ep is None:
            raise ValueError(f"IP '{ip}' absente des traces — appelle d'abord load_traces.")

        # Résolution (réutilise le cache si resolve_asn a déjà été appelé)
        info = self.resolved.get(ip) or self._resolve_one(ip)
        rep = info["reputation"]
        org = info["org"]

        sl = _self_loop_for(self.graph, ep, org)
        c = classify(dst_ip=ip, bytes_total=ep.bytes_total, distinct_ports=len(ep.ports),
                     self_loop=sl, reputation=rep, label_type=self.graph.label_type,
                     packets_total=ep.packets_total, nb_flows=ep.nb_flows,
                     thresholds=self.thresholds)

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
        cor = c.evidence["corroboration"]
        ids_limit = cor["count_a"] if c.primary in ("dos", "port_scan") else None

        transition = {
            # "id" assigné à l'assemblage (tri par IP, comme la Condition A)
            "from": "INITIAL",
            "to": (org or ep.dstname or ip),
            "label": f"{c.primary} → {org or ip}",
            "network_call": {"ip": ip, "port": port, "protocol": proto,
                             "hostname": ep.dstname},
            "service": {"name": org or ep.dstname or ip, "type": "unknown",
                        "reputation": rep_json, "asn": info["asn"], "asn_org": org},
            "suspicion": {
                "score": score, "flags": flags,
                "notes": (f"catégorie={c.primary}; rep_asn={rep}; self_loop={round(sl,3)}; "
                          f"bytes={ep.bytes_total}; ports={len(ep.ports)}; "
                          f"flux={ep.nb_flows}; tier={c.defense_tier}"),
            },
            "behavior": {"probability": round(sl, 3) if sl > 0 else 1.0},
            "metrics": {"count_a": cor["count_a"], "avg_size": cor["avg_size"],
                        "ip_limit_met": cor["ip_limit_met"],
                        "min_size_met": cor["min_size_met"], "ids_limit_n": ids_limit},
        }
        self.classified[ip] = transition
        self.decisions[ip] = {"category": c.primary, "flags": list(flags),
                              "score": score, "reputation": rep_json}

        # Sortie LLM-friendly (résumé décisionnel ; transition complète mémorisée)
        return {"ip": ip, "category": c.primary, "flags": flags, "score": score,
                "reputation": rep_json, "defense_tier": c.defense_tier,
                "port": port, "protocol": proto}

    # --------------------------------------------------------------- assembly
    def all_destination_ips(self) -> list[str]:
        """IP destinations RÉELLES (vérité terrain pour la couverture)."""
        return sorted(self._endpoints.keys())

    def coverage(self) -> dict:
        total = len(self._endpoints)
        done = len(self.classified)
        missed = sorted(set(self._endpoints) - set(self.classified))
        return {"total": total, "classified": done,
                "ratio": round(done / total, 4) if total else 0.0,
                "missed": missed}

    def assemble_transitions(self) -> list[dict]:
        """Transitions B-det : seules les destinations EFFECTIVEMENT classées,
        triées par IP, avec id ``tNN`` (comme la Condition A)."""
        transitions = []
        for idx, ip in enumerate(sorted(self.classified), start=1):
            t = dict(self.classified[ip])
            t["id"] = f"t{idx:02d}"
            transitions.append(t)
        return transitions

    def assemble_states(self) -> list[dict]:
        """États repris des nœuds DOT (le pipeline n'en lit que le nombre)."""
        if self.graph is None:
            return []
        return [{"id": n.node_id, "name": n.label,
                 "type": "control" if n.is_special else "destination"}
                for n in self.graph.nodes.values()]
