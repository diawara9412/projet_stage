"""
tools/firewall_verification_tools.py — Outils de VÉRIFICATION des règles firewall
produites par le FirewallAgent (LLM).

Ces outils ne GÉNÈRENT aucune règle : ils INSPECTENT les règles produites par le
LLM et SIGNALENT les problèmes. C'est le contrepoids au LLM décisionnaire :
le LLM raisonne et propose, les outils vérifient et rapportent.

Chaque fonction prend les règles produites (list[FirewallRule]) — et le
diagnostic (AutomateAnalysis) quand c'est nécessaire — et retourne une
``list[dict]`` de problèmes. Chaque problème : ``{"rule_id": str|None, "message": str}``.
Liste vide = aucun problème.

Style aligné sur tools/chain_tools.py (fonctions déterministes, sans LLM).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from state import AutomateAnalysis, FirewallRule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

# IP du LAN interne Mininet — utilisée par les règles par défaut, jamais une menace.
_LAN_IPV4 = "10.0.0.0/24"

_ALLOW_ACTIONS = ("ALLOW", "ALLOW_AND_INSPECT")


def _is_lan_default(rule: "FirewallRule") -> bool:
    """Vrai si la règle est une règle LAN par défaut (ARP / IPv4 interne / ICMP).

    Ces règles ne ciblent pas une menace ou un service externe : on les exclut
    des vérifications d'hallucination.
    """
    proto = (rule.protocol or "").upper()
    if proto == "ARP":
        return True
    if rule.dst_ip == _LAN_IPV4:  # IPv4 LAN (protocol any) ou ICMP interne
        return True
    return False


def _match_key(rule: "FirewallRule") -> tuple:
    """Clé de correspondance d'une règle : (dst_ip, dst_port, protocole normalisé)."""
    return (rule.dst_ip, rule.dst_port, (rule.protocol or "").upper())


# ---------------------------------------------------------------------------
# 1. Hallucinations — IPs inventées par le LLM
# ---------------------------------------------------------------------------

def check_hallucinated_ips(
    rules: list["FirewallRule"], analysis: "AutomateAnalysis"
) -> list[dict]:
    """Détecte les IPs qui n'existent PAS dans le diagnostic (hallucinations).

    Règle de cohérence :
      - chaque BLOCK doit cibler une IP présente dans ``suspicious_transitions`` ;
      - chaque ALLOW (hors règles LAN par défaut) doit cibler une IP présente
        dans ``legitimate_services``.
    Toute IP absente du diagnostic est une hallucination du LLM.

    Returns:
        Liste de problèmes ``{"rule_id", "message"}``.
    """
    suspicious_ips = {t.dst_ip for t in analysis.suspicious_transitions}
    # Toutes les IPs légitimes (primaires ET secondaires)
    legit_ips: set[str] = set()
    for svc in analysis.legitimate_services:
        legit_ips.update(svc.ips)

    problems: list[dict] = []
    for r in rules:
        if _is_lan_default(r):
            continue  # les règles LAN ne ciblent aucune IP du diagnostic
        if r.dst_ip is None:
            continue  # dst_ip nul = champ manquant (check_required_fields), PAS une hallucination
        if r.action == "BLOCK":
            if r.dst_ip not in suspicious_ips:
                problems.append({
                    "rule_id": r.id,
                    "message": (
                        f"HALLUCINATION : BLOCK vers {r.dst_ip} — cette IP n'est "
                        f"dans AUCUNE transition suspecte du diagnostic."
                    ),
                })
        elif r.action in _ALLOW_ACTIONS:
            if r.dst_ip not in legit_ips:
                problems.append({
                    "rule_id": r.id,
                    "message": (
                        f"HALLUCINATION : ALLOW vers {r.dst_ip} — cette IP n'est "
                        f"dans AUCUN service légitime du diagnostic."
                    ),
                })
    return problems


# ---------------------------------------------------------------------------
# 2. Conflits — BLOCK et ALLOW sur la même cible
# ---------------------------------------------------------------------------

def check_conflicts(rules: list["FirewallRule"]) -> list[dict]:
    """Détecte les conflits BLOCK/ALLOW sur la même (IP, port, protocole).

    Une même cible ne peut pas être à la fois bloquée et autorisée : c'est une
    contradiction de politique.

    Returns:
        Liste de problèmes ``{"rule_id", "message"}``.
    """
    by_key: dict[tuple, list["FirewallRule"]] = {}
    for r in rules:
        by_key.setdefault(_match_key(r), []).append(r)

    problems: list[dict] = []
    for key, group in by_key.items():
        actions = {r.action for r in group}
        has_block = "BLOCK" in actions
        has_allow = bool(set(_ALLOW_ACTIONS) & actions)
        if has_block and has_allow:
            ids = ", ".join(r.id for r in group)
            problems.append({
                "rule_id": ids,
                "message": (
                    f"CONFLIT : BLOCK et ALLOW coexistent sur {key[0]}:{key[1]}/{key[2]} "
                    f"(règles {ids})."
                ),
            })
    return problems


# ---------------------------------------------------------------------------
# 3. Redondance — règles dupliquées
# ---------------------------------------------------------------------------

def check_redundancy(rules: list["FirewallRule"]) -> list[dict]:
    """Détecte les règles strictement redondantes (même action + même match).

    Clé de doublon : (action, dst_ip, dst_port, protocole, direction).

    Returns:
        Liste de problèmes ``{"rule_id", "message"}`` (un par doublon détecté).
    """
    seen: dict[tuple, str] = {}
    problems: list[dict] = []
    for r in rules:
        key = (r.action, r.dst_ip, r.dst_port, (r.protocol or "").upper(), r.direction)
        if key in seen:
            problems.append({
                "rule_id": r.id,
                "message": (
                    f"DOUBLON : {r.id} est identique à {seen[key]} "
                    f"({r.action} {r.dst_ip}:{r.dst_port}/{r.protocol})."
                ),
            })
        else:
            seen[key] = r.id
    return problems


# ---------------------------------------------------------------------------
# 4. Champs obligatoires — règle complète et bien formée
# ---------------------------------------------------------------------------

def check_required_fields(rules: list["FirewallRule"]) -> list[dict]:
    """Vérifie que chaque règle a ses champs obligatoires correctement remplis.

    Contrôles :
      - ``id`` non vide ;
      - ``comment`` non vide ;
      - ``priority`` dans l'intervalle 0–1000 ;
      - ``dst_ip`` renseigné SAUF pour ARP (protocole L2 sans IP).

    (Le typage des champs — action/protocol/direction dans leurs Literal — est
    déjà garanti par la construction du modèle FirewallRule en amont.)

    Returns:
        Liste de problèmes ``{"rule_id", "message"}``.
    """
    problems: list[dict] = []
    for r in rules:
        if not r.id:
            problems.append({"rule_id": None, "message": "CHAMP MANQUANT : id vide."})
        if not (r.comment or "").strip():
            problems.append({"rule_id": r.id, "message": f"CHAMP MANQUANT : comment vide ({r.id})."})
        if not (0 <= r.priority <= 1000):
            problems.append({
                "rule_id": r.id,
                "message": f"CHAMP INVALIDE : priority={r.priority} hors de [0, 1000] ({r.id}).",
            })
        if r.dst_ip is None and (r.protocol or "").upper() != "ARP":
            problems.append({
                "rule_id": r.id,
                "message": f"CHAMP MANQUANT : dst_ip absent pour une règle non-ARP ({r.id}).",
            })
    return problems


# ---------------------------------------------------------------------------
# 5. Règles LAN par défaut — présence des 3 garde-fous
# ---------------------------------------------------------------------------

def check_lan_defaults(rules: list["FirewallRule"]) -> list[dict]:
    """Vérifie la présence des 3 règles LAN par défaut indispensables.

    Sans elles, le mode failMode=secure des switches OVS bloquerait le trafic
    interne (ARP, ping, IPv4 LAN). On exige donc :
      - 1 ALLOW ARP ;
      - 1 ALLOW IPv4 LAN (10.0.0.0/24, protocole any) ;
      - 1 ALLOW ICMP interne (10.0.0.0/24).

    Returns:
        Liste de problèmes ``{"rule_id": None, "message"}`` (un par règle manquante).
    """
    has_arp = any((r.protocol or "").upper() == "ARP" for r in rules)
    has_lan_ipv4 = any(
        r.dst_ip == _LAN_IPV4 and (r.protocol or "").upper() == "ANY" for r in rules
    )
    has_icmp = any(
        r.dst_ip == _LAN_IPV4 and (r.protocol or "").upper() == "ICMP" for r in rules
    )

    problems: list[dict] = []
    if not has_arp:
        problems.append({"rule_id": None, "message": "LAN MANQUANT : règle ALLOW ARP absente."})
    if not has_lan_ipv4:
        problems.append({"rule_id": None, "message": "LAN MANQUANT : règle ALLOW IPv4 10.0.0.0/24 (any) absente."})
    if not has_icmp:
        problems.append({"rule_id": None, "message": "LAN MANQUANT : règle ALLOW ICMP 10.0.0.0/24 absente."})
    return problems


# ---------------------------------------------------------------------------
# Agrégateur pratique — lance les 5 vérifications d'un coup
# ---------------------------------------------------------------------------

def run_all_checks(
    rules: list["FirewallRule"], analysis: "AutomateAnalysis"
) -> dict[str, list[dict]]:
    """Exécute les 5 outils et retourne un dict par catégorie de problème.

    Returns:
        ``{"hallucinations": [...], "conflicts": [...], "redundancies": [...],
           "missing_fields": [...], "lan_problems": [...]}``
    """
    return {
        "hallucinations": check_hallucinated_ips(rules, analysis),
        "conflicts": check_conflicts(rules),
        "redundancies": check_redundancy(rules),
        "missing_fields": check_required_fields(rules),
        "lan_problems": check_lan_defaults(rules),
    }
