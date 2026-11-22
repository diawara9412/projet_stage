"""
tools/ids_verification_tools.py — Outils de VÉRIFICATION des signatures IDS
produites par l'IDSAgent (LLM).

Comme pour le firewall, ces outils ne GÉNÈRENT aucune signature : ils INSPECTENT
celles produites par le LLM et SIGNALENT les problèmes. Le LLM raisonne et
propose ; les outils vérifient et rapportent.

Chaque fonction prend les signatures (list[IdsSignature]) — et le diagnostic
(AutomateAnalysis) quand nécessaire — et retourne une ``list[dict]`` de problèmes.
Chaque problème : ``{"sig_id": str|None, "message": str}``. Liste vide = OK.

Style aligné sur tools/firewall_verification_tools.py.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from state import AutomateAnalysis, IdsSignature

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

def _criteria_ip(sig: "IdsSignature") -> str | None:
    """Extrait le dst_ip du match_criteria (tolérant si absent)."""
    mc = sig.match_criteria or {}
    return mc.get("dst_ip") if isinstance(mc, dict) else None


def _criteria_port(sig: "IdsSignature"):
    """Extrait le dst_port du match_criteria (tolérant si absent)."""
    mc = sig.match_criteria or {}
    return mc.get("dst_port") if isinstance(mc, dict) else None


# ---------------------------------------------------------------------------
# 1. Hallucinations — cibles inventées par le LLM
# ---------------------------------------------------------------------------

def check_hallucinated_targets(
    signatures: list["IdsSignature"], analysis: "AutomateAnalysis"
) -> list[dict]:
    """Détecte les signatures dont la cible n'existe pas dans le diagnostic.

    Chaque ``match_criteria.dst_ip`` doit correspondre à une transition suspecte
    réelle. Toute IP absente du diagnostic est une hallucination du LLM.

    Returns:
        Liste de problèmes ``{"sig_id", "message"}``.
    """
    suspicious_ips = {t.dst_ip for t in analysis.suspicious_transitions}

    problems: list[dict] = []
    for s in signatures:
        ip = _criteria_ip(s)
        if ip is None:
            continue  # dst_ip absent du match_criteria = champ manquant, PAS une hallucination
        if ip not in suspicious_ips:
            problems.append({
                "sig_id": s.id,
                "message": (
                    f"HALLUCINATION : signature {s.id} ({s.pattern_type}) cible "
                    f"{ip} — absente des transitions suspectes du diagnostic."
                ),
            })
    return problems


# ---------------------------------------------------------------------------
# 2. Redondance — signatures dupliquées
# ---------------------------------------------------------------------------

def check_redundancy(signatures: list["IdsSignature"]) -> list[dict]:
    """Détecte les signatures redondantes (même pattern_type + même cible).

    Clé de doublon : (pattern_type, dst_ip, dst_port).

    Returns:
        Liste de problèmes ``{"sig_id", "message"}`` (un par doublon).
    """
    seen: dict[tuple, str] = {}
    problems: list[dict] = []
    for s in signatures:
        key = (s.pattern_type, _criteria_ip(s), _criteria_port(s))
        if key in seen:
            problems.append({
                "sig_id": s.id,
                "message": (
                    f"DOUBLON : {s.id} est identique à {seen[key]} "
                    f"({s.pattern_type} sur {_criteria_ip(s)})."
                ),
            })
        else:
            seen[key] = s.id
    return problems


# ---------------------------------------------------------------------------
# 3. Champs obligatoires — signature complète et bien formée
# ---------------------------------------------------------------------------

def check_required_fields(signatures: list["IdsSignature"]) -> list[dict]:
    """Vérifie que chaque signature a ses champs obligatoires remplis.

    Contrôles :
      - ``id`` non vide ;
      - ``name`` non vide ;
      - ``pattern_type`` présent (le typage Literal est garanti par le modèle) ;
      - ``match_criteria`` non vide ET contenant au moins ``dst_ip`` ;
      - ``severity`` présente.

    Returns:
        Liste de problèmes ``{"sig_id", "message"}``.
    """
    problems: list[dict] = []
    for s in signatures:
        if not s.id:
            problems.append({"sig_id": None, "message": "CHAMP MANQUANT : id vide."})
        if not (s.name or "").strip():
            problems.append({"sig_id": s.id, "message": f"CHAMP MANQUANT : name vide ({s.id})."})
        if not s.match_criteria or not isinstance(s.match_criteria, dict):
            problems.append({"sig_id": s.id, "message": f"CHAMP MANQUANT : match_criteria vide ({s.id})."})
        elif not s.match_criteria.get("dst_ip"):
            problems.append({
                "sig_id": s.id,
                "message": f"CHAMP MANQUANT : match_criteria sans dst_ip ({s.id}).",
            })
        if not s.severity:
            problems.append({"sig_id": s.id, "message": f"CHAMP MANQUANT : severity vide ({s.id})."})
    return problems


# ---------------------------------------------------------------------------
# 4. Couverture — toute menace suspecte est surveillée
# ---------------------------------------------------------------------------

def check_coverage(
    signatures: list["IdsSignature"], analysis: "AutomateAnalysis"
) -> list[dict]:
    """Vérifie que chaque transition suspecte est couverte par ≥1 signature.

    Une transition suspecte sans aucune signature qui surveille son IP est une
    menace NON surveillée — lacune de détection.

    Returns:
        Liste de problèmes ``{"sig_id": None, "message"}`` (un par IP non couverte).
    """
    covered_ips = {_criteria_ip(s) for s in signatures}

    problems: list[dict] = []
    seen_ips: set[str] = set()
    for t in analysis.suspicious_transitions:
        if t.dst_ip in seen_ips:
            continue
        seen_ips.add(t.dst_ip)
        if t.dst_ip not in covered_ips:
            problems.append({
                "sig_id": None,
                "message": (
                    f"COUVERTURE MANQUANTE : la transition suspecte {t.transition_id} "
                    f"({t.dst_ip}:{t.dst_port}, flags={t.flags}) n'est surveillée par "
                    f"AUCUNE signature."
                ),
            })
    return problems


# ---------------------------------------------------------------------------
# Agrégateur pratique — lance les 4 vérifications d'un coup
# ---------------------------------------------------------------------------

def run_all_checks(
    signatures: list["IdsSignature"], analysis: "AutomateAnalysis"
) -> dict[str, list[dict]]:
    """Exécute les 4 outils et retourne un dict par catégorie de problème.

    Returns:
        ``{"hallucinations": [...], "redundancies": [...],
           "missing_fields": [...], "coverage": [...]}``
    """
    return {
        "hallucinations": check_hallucinated_targets(signatures, analysis),
        "redundancies": check_redundancy(signatures),
        "missing_fields": check_required_fields(signatures),
        "coverage": check_coverage(signatures, analysis),
    }
