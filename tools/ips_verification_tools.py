"""
tools/ips_verification_tools.py — Outils de VÉRIFICATION des actions IPS
produites par l'IPSAgent (LLM).

Comme pour firewall et IDS, ces outils ne GÉNÈRENT aucune action : ils
INSPECTENT celles produites par le LLM et SIGNALENT les problèmes.

PARTICULARITÉ IPS : l'outil central est ``check_orphan_references`` — chaque
action référence une signature IDS via ``on_signature``, et cette référence
DOIT exister. Une référence cassée = orphelin (action qui ne peut jamais être
armée), rejetée par le validateur.

Chaque fonction prend les actions (list[IpsAction]) — et les signatures IDS
(list[IdsSignature]) quand nécessaire — et retourne une ``list[dict]`` de
problèmes ``{"act_id": str|None, "message": str}``. Liste vide = OK.

Style aligné sur tools/ids_verification_tools.py.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from state import IdsSignature, IpsAction

logger = logging.getLogger(__name__)

# Ensemble d'actions IPS autorisé par le projet (REDIRECT_HONEYPOT exclu ici).
_VALID_ACTIONS = {"DROP_SOURCE", "RATE_LIMIT", "QUARANTINE", "ALERT_ONLY"}


# ---------------------------------------------------------------------------
# 1. Références orphelines — L'OUTIL CRITIQUE
# ---------------------------------------------------------------------------

def check_orphan_references(
    actions: list["IpsAction"], ids_signatures: list["IdsSignature"]
) -> list[dict]:
    """Détecte les actions dont le ``on_signature`` ne correspond à aucune signature.

    C'est la vérification centrale de l'IPS : une action qui arme une signature
    inexistante ne se déclenchera jamais (orphelin) et serait rejetée comme
    ``orphan_reference`` (ERROR) par le ChainValidator.

    Returns:
        Liste de problèmes ``{"act_id", "message"}``.
    """
    valid_ids = {s.id for s in ids_signatures}

    problems: list[dict] = []
    for a in actions:
        if not a.on_signature:
            continue  # on_signature vide = champ manquant (check_required_fields), PAS un orphelin
        if a.on_signature not in valid_ids:
            problems.append({
                "act_id": a.id,
                "message": (
                    f"ORPHELIN : action {a.id} ({a.action}) référence la signature "
                    f"'{a.on_signature}' — inexistante. IDs valides : {sorted(valid_ids)}."
                ),
            })
    return problems


# ---------------------------------------------------------------------------
# 2. Redondance — actions dupliquées
# ---------------------------------------------------------------------------

def check_redundancy(actions: list["IpsAction"]) -> list[dict]:
    """Détecte les actions redondantes (même signature armée par la même action).

    Clé de doublon : (on_signature, action).

    Returns:
        Liste de problèmes ``{"act_id", "message"}`` (un par doublon).
    """
    seen: dict[tuple, str] = {}
    problems: list[dict] = []
    for a in actions:
        key = (a.on_signature, a.action)
        if key in seen:
            problems.append({
                "act_id": a.id,
                "message": (
                    f"DOUBLON : {a.id} est identique à {seen[key]} "
                    f"({a.action} sur {a.on_signature})."
                ),
            })
        else:
            seen[key] = a.id
    return problems


# ---------------------------------------------------------------------------
# 3. Champs obligatoires — action complète et bien formée
# ---------------------------------------------------------------------------

def check_required_fields(actions: list["IpsAction"]) -> list[dict]:
    """Vérifie que chaque action a ses champs obligatoires remplis.

    Contrôles :
      - ``id`` non vide ;
      - ``on_signature`` non vide ;
      - ``action`` présente ;
      - si ``action == RATE_LIMIT`` : ``rate_limit_pps`` doit être renseigné
        (sinon la limitation de débit n'a pas de valeur).

    Returns:
        Liste de problèmes ``{"act_id", "message"}``.
    """
    problems: list[dict] = []
    for a in actions:
        if not a.id:
            problems.append({"act_id": None, "message": "CHAMP MANQUANT : id vide."})
        if not (a.on_signature or "").strip():
            problems.append({"act_id": a.id, "message": f"CHAMP MANQUANT : on_signature vide ({a.id})."})
        if not (a.action or "").strip():
            problems.append({"act_id": a.id, "message": f"CHAMP MANQUANT : action vide ({a.id})."})
        if a.action == "RATE_LIMIT" and a.rate_limit_pps is None:
            problems.append({
                "act_id": a.id,
                "message": f"CHAMP MANQUANT : RATE_LIMIT sans rate_limit_pps ({a.id}).",
            })
    return problems


# ---------------------------------------------------------------------------
# 4. Validité de l'action — pas d'action inventée
# ---------------------------------------------------------------------------

def check_action_validity(actions: list["IpsAction"]) -> list[dict]:
    """Vérifie que chaque ``action`` appartient à l'ensemble autorisé.

    Ensemble autorisé : DROP_SOURCE, RATE_LIMIT, QUARANTINE, ALERT_ONLY.

    Returns:
        Liste de problèmes ``{"act_id", "message"}``.
    """
    problems: list[dict] = []
    for a in actions:
        if a.action not in _VALID_ACTIONS:
            problems.append({
                "act_id": a.id,
                "message": (
                    f"ACTION INVALIDE : {a.id} a action='{a.action}' — "
                    f"hors de {sorted(_VALID_ACTIONS)}."
                ),
            })
    return problems


# ---------------------------------------------------------------------------
# 5. Couverture — chaque signature est armée
# ---------------------------------------------------------------------------

def check_coverage(
    actions: list["IpsAction"], ids_signatures: list["IdsSignature"]
) -> list[dict]:
    """Vérifie que chaque signature IDS est armée par au moins une action.

    Une signature détectée mais sans action IPS ne déclenche aucune réponse :
    détection passive sans réaction.

    Returns:
        Liste de problèmes ``{"act_id": None, "message"}`` (un par signature non armée).
    """
    armed = {a.on_signature for a in actions}

    problems: list[dict] = []
    for s in ids_signatures:
        if s.id not in armed:
            problems.append({
                "act_id": None,
                "message": (
                    f"COUVERTURE MANQUANTE : la signature {s.id} ({s.pattern_type}, "
                    f"{s.severity}) n'est armée par AUCUNE action IPS."
                ),
            })
    return problems


# ---------------------------------------------------------------------------
# Agrégateur pratique — lance les 5 vérifications d'un coup
# ---------------------------------------------------------------------------

def run_all_checks(
    actions: list["IpsAction"], ids_signatures: list["IdsSignature"]
) -> dict[str, list[dict]]:
    """Exécute les 5 outils et retourne un dict par catégorie de problème.

    Returns:
        ``{"orphans": [...], "redundancies": [...], "missing_fields": [...],
           "invalid_actions": [...], "coverage": [...]}``
    """
    return {
        "orphans": check_orphan_references(actions, ids_signatures),
        "redundancies": check_redundancy(actions),
        "missing_fields": check_required_fields(actions),
        "invalid_actions": check_action_validity(actions),
        "coverage": check_coverage(actions, ids_signatures),
    }
