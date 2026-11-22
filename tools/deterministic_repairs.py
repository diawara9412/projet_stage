"""
tools/deterministic_repairs.py — Réparations DÉTERMINISTES sûres pour les chaînes
de sécurité (firewall / IDS / IPS).

Corrections MÉCANIQUES sans jugement, réutilisées par la boucle de correction
(architectures/supervisor/correction_loop.py). Aucun appel LLM.

CARVE-OUT IMPORTANT (décision projet) : la DÉDUPLICATION n'est PAS faite ici. Les
doublons restent volontairement dans la sortie de l'agent ; seul ``validate_chain``
les retire en fin de pipeline et le score reste pénalisé — le doublon est un signal
scientifique de la qualité de raisonnement du LLM, qu'on ne veut pas effacer.

Réparations fournies :
  - collect_problem_ids : extrait les ids fautifs d'une liste de problèmes d'outils
  - drop_items          : retire des éléments par id (générique)
  - add_missing_lan     : ajoute les 3 règles LAN par défaut si absentes (firewall)
  - fix_block_priority  : remonte la priorité des BLOCK sous un ALLOW (firewall)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from state import FirewallRule

logger = logging.getLogger(__name__)

_LAN_IPV4 = "10.0.0.0/24"


# ---------------------------------------------------------------------------
# Génériques
# ---------------------------------------------------------------------------

def collect_problem_ids(problems: list[dict]) -> set[str]:
    """Extrait les ids fautifs d'une liste de problèmes d'outils.

    Tolère les clés ``rule_id`` / ``sig_id`` / ``act_id`` selon la famille.
    Ignore les problèmes sans id (ex. couverture manquante, qui n'ont pas d'id).
    """
    ids: set[str] = set()
    for p in problems:
        for key in ("rule_id", "sig_id", "act_id"):
            v = p.get(key)
            if v:
                ids.add(v)
    return ids


def drop_items(items: list, ids_to_drop: set[str]) -> list:
    """Retourne la liste sans les éléments dont l'``id`` est à jeter."""
    if not ids_to_drop:
        return list(items)
    return [it for it in items if getattr(it, "id", None) not in ids_to_drop]


def dedup_by(items: list, key_fn) -> tuple[list, int]:
    """Déduplique en gardant la 1ʳᵉ occurrence de chaque clé.

    (Décision projet : la dédup fait DÉSORMAIS partie des corrections — la chaîne
    finale doit être propre. Le compte des doublons d'origine est conservé à part,
    via ``errors_before_correction``, pour la mesure scientifique.)

    Args:
        items: liste d'éléments (FirewallRule / IdsSignature / IpsAction).
        key_fn: fonction renvoyant la clé d'unicité d'un élément.

    Returns:
        (liste dédupliquée, nombre d'éléments retirés).
    """
    seen: set = set()
    kept: list = []
    removed = 0
    for it in items:
        k = key_fn(it)
        if k in seen:
            removed += 1
            continue
        seen.add(k)
        kept.append(it)
    return kept, removed


# ---------------------------------------------------------------------------
# Réparations spécifiques firewall
# ---------------------------------------------------------------------------

def add_missing_lan(fw_rules: list["FirewallRule"]) -> tuple[list["FirewallRule"], list[str]]:
    """Ajoute les règles LAN par défaut manquantes (ARP / IPv4 interne / ICMP).

    Ces 3 règles sont fixes et connues : leur ajout est purement mécanique et sûr.
    Sur une sortie déjà correcte (LAN présentes), ne modifie RIEN.

    Returns:
        (règles complétées, journal des ajouts).
    """
    from state import FirewallRule

    has_arp = any((r.protocol or "").upper() == "ARP" for r in fw_rules)
    has_lan_ipv4 = any(
        r.dst_ip == _LAN_IPV4 and (r.protocol or "").upper() == "ANY" for r in fw_rules
    )
    has_icmp = any(
        r.dst_ip == _LAN_IPV4 and (r.protocol or "").upper() == "ICMP" for r in fw_rules
    )

    added: list[FirewallRule] = []
    fixes: list[str] = []
    if not has_lan_ipv4:
        added.append(FirewallRule(
            id="FW-LAN-IPV4", action="ALLOW", direction="both",
            dst_ip=_LAN_IPV4, dst_port=None, protocol="any", priority=50,
            source_transition_id=None,
            comment="Règle LAN IPv4 ajoutée automatiquement (réparation déterministe)",
        ))
        fixes.append("LAN IPv4 10.0.0.0/24 ajoutée (manquait)")
    if not has_arp:
        added.append(FirewallRule(
            id="FW-LAN-ARP", action="ALLOW", direction="both",
            dst_ip=None, dst_port=None, protocol="ARP", priority=50,
            source_transition_id=None,
            comment="Règle LAN ARP ajoutée automatiquement (réparation déterministe)",
        ))
        fixes.append("LAN ARP ajoutée (manquait)")
    if not has_icmp:
        added.append(FirewallRule(
            id="FW-LAN-ICMP", action="ALLOW", direction="both",
            dst_ip=_LAN_IPV4, dst_port=None, protocol="ICMP", priority=50,
            source_transition_id=None,
            comment="Règle LAN ICMP ajoutée automatiquement (réparation déterministe)",
        ))
        fixes.append("LAN ICMP ajoutée (manquait)")

    return list(fw_rules) + added, fixes


def fix_block_priority(fw_rules: list["FirewallRule"]) -> tuple[list["FirewallRule"], list[str]]:
    """Remonte la priorité des BLOCK qui ne dominent pas un ALLOW sur la même IP.

    Pour chaque IP où min(BLOCK.priority) <= max(ALLOW.priority), on remonte les
    BLOCK concernés à max(ALLOW)+50 (plafonné à 1000). Mécanique, sans jugement.
    Sur une sortie déjà correcte (BLOCK 900 > ALLOW 100), ne modifie RIEN.

    Returns:
        (règles corrigées, journal des corrections).
    """
    allow_max: dict[str, int] = {}
    for r in fw_rules:
        if r.dst_ip and r.action in ("ALLOW", "ALLOW_AND_INSPECT"):
            allow_max[r.dst_ip] = max(allow_max.get(r.dst_ip, 0), r.priority)

    out: list = []
    fixes: list[str] = []
    for r in fw_rules:
        if (r.dst_ip and r.action == "BLOCK"
                and r.dst_ip in allow_max and r.priority <= allow_max[r.dst_ip]):
            new_prio = min(1000, allow_max[r.dst_ip] + 50)
            out.append(r.model_copy(update={"priority": new_prio}))
            fixes.append(f"priorité de {r.id} remontée à {new_prio} (> ALLOW sur {r.dst_ip})")
        else:
            out.append(r)
    return out, fixes
