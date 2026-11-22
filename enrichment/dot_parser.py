"""
enrichment/dot_parser.py — Parseur des automates au format DOT (Graphviz).

Étape 1 de la couche d'enrichissement. Extrait, pour un fichier .dot :
  - les NŒUDS : id, label, shape, et s'ils sont spéciaux (INITIAL/TERMINAL) ;
  - les ARÊTES : (source, destination, probabilité) — la proba vient du label "P:<x>" ;
  - le SELF-LOOP par nœud : P(n→n) (0.0 si absent) — signal de beaconing/worm ;
  - le TYPE de label détecté : "ORG" (noms d'organisation) vs "PORT" (numéros de port)
    vs "MIXED"/"UNKNOWN".

Ce module NE fait QUE parser le DOT : pas de CSV, pas de résolution ASN, pas de
classification. Dépendance : pydot (déjà installé). Aucun réseau, aucun LLM.
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass, field

import pydot

# Labels de nœuds « techniques » de l'automate (états de contrôle, pas des destinations)
_SPECIAL_LABELS = {"INITIAL", "TERMINAL"}

# Un label est « port-like » s'il est : un entier (443), un entier/sous-canal (4244/4),
# ou le joker "*". Sinon il est considéré « org-like » (nom d'organisation/ASN).
_PORT_RE = re.compile(r"^(\*|\d+(/\d+)?)$")

# Noms internes que pydot peut renvoyer comme « nœuds » d'attributs par défaut.
_PYDOT_DEFAULT_NODES = {"node", "graph", "edge"}


# ---------------------------------------------------------------------------
# Structures de données internes
# ---------------------------------------------------------------------------

@dataclass
class DotNode:
    node_id: str
    label: str
    shape: str | None
    is_special: bool          # True pour INITIAL / TERMINAL


@dataclass
class DotEdge:
    src: str
    dst: str
    probability: float | None  # extraite de "P:<x>", None si absente


@dataclass
class AutomatonGraph:
    name: str                                   # nom de l'app (stem du fichier)
    nodes: dict[str, DotNode] = field(default_factory=dict)
    edges: list[DotEdge] = field(default_factory=list)
    self_loops: dict[str, float] = field(default_factory=dict)  # node_id → P(n→n)
    label_type: str = "UNKNOWN"                 # ORG | PORT | MIXED | UNKNOWN

    # --- accès pratiques (lecture seule) ---
    def destination_nodes(self) -> list[DotNode]:
        """Nœuds 'destination' réels (hors INITIAL/TERMINAL)."""
        return [n for n in self.nodes.values() if not n.is_special]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unquote(value: str | None) -> str | None:
    """Retire les guillemets que pydot conserve autour des attributs."""
    if value is None:
        return None
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v


def _label_kind(label: str) -> str:
    """Classe un label : 'port' (numérique/joker) ou 'org' (texte)."""
    return "port" if _PORT_RE.match((label or "").strip()) else "org"


def _parse_probability(edge_label: str | None) -> float | None:
    """Extrait la proba d'un label d'arête de la forme 'P:0.64'."""
    if not edge_label:
        return None
    m = re.search(r"P:\s*([0-9]*\.?[0-9]+)", edge_label)
    return float(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Parseur principal
# ---------------------------------------------------------------------------

def parse_dot_file(path: str | pathlib.Path) -> AutomatonGraph:
    """Parse un fichier .dot et retourne un AutomatonGraph.

    Raises:
        FileNotFoundError: si le fichier n'existe pas.
        ValueError: si pydot ne renvoie aucun graphe exploitable.
    """
    path = pathlib.Path(path)
    if not path.exists():
        raise FileNotFoundError(f"DOT introuvable : {path}")

    graphs = pydot.graph_from_dot_file(str(path))
    if not graphs:
        raise ValueError(f"Aucun graphe DOT exploitable dans {path}")
    g = graphs[0]

    # ── Nœuds ───────────────────────────────────────────────────────────────
    nodes: dict[str, DotNode] = {}
    for n in g.get_nodes():
        nid = n.get_name().strip().strip('"')
        if nid in _PYDOT_DEFAULT_NODES or nid == "":
            continue
        attrs = n.get_attributes()
        label = _unquote(attrs.get("label")) or nid
        shape = _unquote(attrs.get("shape"))
        is_special = label.upper() in _SPECIAL_LABELS
        nodes[nid] = DotNode(node_id=nid, label=label, shape=shape, is_special=is_special)

    # ── Arêtes ──────────────────────────────────────────────────────────────
    edges: list[DotEdge] = []
    for e in g.get_edges():
        src = e.get_source().strip().strip('"')
        dst = e.get_destination().strip().strip('"')
        prob = _parse_probability(_unquote(e.get_attributes().get("label")))
        edges.append(DotEdge(src=src, dst=dst, probability=prob))
        # Sécurité : si une arête référence un nœud non déclaré, on le crée minimal.
        for ref in (src, dst):
            if ref not in nodes:
                nodes[ref] = DotNode(node_id=ref, label=ref, shape=None,
                                     is_special=ref.upper() in _SPECIAL_LABELS)

    # ── Self-loops P(n→n) ────────────────────────────────────────────────────
    self_loops: dict[str, float] = {nid: 0.0 for nid in nodes}
    for e in edges:
        if e.src == e.dst:
            self_loops[e.src] = e.probability if e.probability is not None else 0.0

    # ── Type de label (en ignorant INITIAL/TERMINAL) ─────────────────────────
    kinds = {_label_kind(n.label) for n in nodes.values() if not n.is_special}
    if not kinds:
        label_type = "UNKNOWN"
    elif kinds == {"port"}:
        label_type = "PORT"
    elif kinds == {"org"}:
        label_type = "ORG"
    else:
        label_type = "MIXED"

    return AutomatonGraph(
        name=path.stem,
        nodes=nodes,
        edges=edges,
        self_loops=self_loops,
        label_type=label_type,
    )


# ---------------------------------------------------------------------------
# Démo / vérification (aucun réseau, aucun LLM)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    targets = sys.argv[1:] or sorted(str(p) for p in (root / "automates").glob("*.dot"))

    for t in targets:
        try:
            a = parse_dot_file(t)
        except Exception as exc:
            print(f"❌ {t} : {exc}")
            continue
        dests = a.destination_nodes()
        specials = [n.label for n in a.nodes.values() if n.is_special]
        print(f"✅ {a.name:<12} type={a.label_type:<7} "
              f"nœuds={len(a.nodes)} (dest={len(dests)}, spéciaux={specials}) "
              f"arêtes={len(a.edges)}")
