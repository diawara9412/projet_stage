"""
tools/chain_tools.py — Outils pour les agents de la Phase 2 (chaînes de sécurité).

Fournit :
- ``load_automate``              : charge et valide un fichier automate JSON depuis le disque
- ``generate_chain_from_analysis``: génère une SecurityChain déterministe depuis une AutomateAnalysis
- ``validate_chain``             : vérifie, corrige et note une SecurityChain
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from langchain_core.tools import tool

if TYPE_CHECKING:
    from state import AutomateAnalysis, SecurityChain

logger = logging.getLogger(__name__)

# Racine du projet : ce fichier est dans tools/, donc parent().parent() = projet/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@tool
def load_automate(path: str) -> dict:
    """Charge et valide un fichier automate JSON depuis le disque.

    Accepte un chemin absolu ou relatif à la racine du projet.
    Valide que les champs ``automate_id``, ``states`` et ``transitions``
    sont présents avant de retourner le contenu.

    Args:
        path: Chemin vers le fichier JSON de l'automate.
              Peut être absolu (``/home/.../pokemon_go.json``)
              ou relatif à la racine du projet (``automates/pokemon_go.json``).

    Returns:
        dict avec ``status: "success"`` et ``automate: {...}`` si réussi,
        ou ``status: "error"`` et ``message: "..."`` si échec.

    Examples:
        >>> result = load_automate.invoke({"path": "automates/pokemon_go.json"})
        >>> result["status"]
        'success'
        >>> result["automate"]["app_name"]
        'Pokemon GO'
    """
    resolved = Path(path) if Path(path).is_absolute() else _PROJECT_ROOT / path

    if not resolved.exists():
        logger.error("Fichier automate introuvable : %s", resolved)
        return {"status": "error", "message": f"Fichier introuvable : {resolved}"}

    if resolved.suffix.lower() != ".json":
        return {"status": "error", "message": f"Le fichier doit être un .json, reçu : {resolved.suffix}"}

    try:
        with resolved.open(encoding="utf-8") as fh:
            automate = json.load(fh)
    except json.JSONDecodeError as exc:
        logger.error("JSON invalide dans %s : %s", resolved, exc)
        return {"status": "error", "message": f"JSON invalide : {exc}"}

    required = ("automate_id", "states", "transitions")
    missing = [f for f in required if f not in automate]
    if missing:
        return {
            "status": "error",
            "message": f"Champs obligatoires manquants dans l'automate : {missing}",
        }

    nb_states = len(automate.get("states", []))
    nb_transitions = len(automate.get("transitions", []))
    logger.info(
        "Automate chargé : '%s' — %d états, %d transitions",
        automate.get("app_name", automate["automate_id"]),
        nb_states,
        nb_transitions,
    )
    return {
        "status": "success",
        "automate": automate,
        "nb_states": nb_states,
        "nb_transitions": nb_transitions,
    }


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

# Mapping : flag de suspicion → type de signature IDS
# (Ajout étape 5 : syn_flood/port_scan pour brancher les catégories DoS/port_scan
#  issues de l'enrichissement. PUREMENT ADDITIF — aucun flag existant modifié.)
_FLAG_TO_IDS_TYPE: dict[str, str] = {
    "tor_exit_node":     "tor_communication",
    "beaconing":         "beaconing",
    "data_exfiltration": "data_exfiltration",
    "dga_domain":        "dga_dns",
    "suspicious_path":   "suspicious_url",
    "syn_flood":         "syn_flood",      # DoS → IDS syn_flood
    "port_scan":         "port_scan",      # scan de ports → IDS port_scan
    "monitored":         "monitored",      # inconnu non-suspect → surveillance légère
}

# Flags de SURVEILLANCE SEULE : produisent un IDS mais PAS de BLOCK (cf. §1).
_MONITORING_ONLY_FLAGS: frozenset[str] = frozenset({"monitored"})

# Priorité d'itération (on veut traiter tor/beaconing avant dga/url)
_FLAG_ORDER: list[str] = [
    "tor_exit_node", "beaconing", "data_exfiltration", "dga_domain", "suspicious_path",
    "syn_flood", "port_scan", "monitored",
]

# Mapping IDS type → sévérité
_IDS_SEVERITY: dict[str, str] = {
    "tor_communication": "CRITICAL",
    "beaconing":         "HIGH",
    "data_exfiltration": "CRITICAL",
    "dga_dns":           "HIGH",
    "suspicious_url":    "MEDIUM",
    "syn_flood":         "HIGH",
    "port_scan":         "MEDIUM",
    "monitored":         "LOW",
}

# Mapping IDS type → action IPS par défaut
_IDS_TO_IPS_ACTION: dict[str, str] = {
    "tor_communication": "DROP_SOURCE",
    "beaconing":         "RATE_LIMIT",
    "data_exfiltration": "DROP_SOURCE",
    "dga_dns":           "ALERT_ONLY",
    "suspicious_url":    "ALERT_ONLY",
    "syn_flood":         "RATE_LIMIT",     # DoS → limitation de débit
    "port_scan":         "ALERT_ONLY",     # scan → alerte
    "monitored":         "ALERT_ONLY",     # surveillance légère (ni DROP ni RATE_LIMIT)
}

# Mapping protocole automate → Literal FirewallRule
_PROTO_MAP: dict[str, str] = {
    "TCP":   "TCP",
    "UDP":   "UDP",
    "ICMP":  "ICMP",
    "HTTP":  "HTTP",
    "HTTPS": "HTTPS",
    "ARP":   "ARP",
    "DNS":   "UDP",
    "gRPC":  "HTTPS",
}


def _norm_proto(raw: str) -> str:
    return _PROTO_MAP.get(raw.upper() if raw else "", "any")


def _norm_risk(raw: str) -> str:
    mapping = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "HIGH"}
    return mapping.get(raw.lower(), "MEDIUM")


# ---------------------------------------------------------------------------
# Génération déterministe de la chaîne de sécurité
# ---------------------------------------------------------------------------

def generate_chain_from_analysis(analysis: "AutomateAnalysis") -> "SecurityChain":
    """Génère une SecurityChain déterministe depuis une AutomateAnalysis.

    Ne nécessite pas de LLM.  La chaîne couvre :
    - 1 règle BLOCK par IP:port unique parmi les transitions suspectes
      (déduplication si plusieurs transitions visent la même IP:port)
    - Des signatures IDS et actions IPS pour chaque flag de suspicion détecté
      (déduplication si même pattern_type + même IP)
    - 1 règle ALLOW par service légitime
    - 1 action QUARANTINE si le risque global est HIGH/CRITICAL

    Args:
        analysis: AutomateAnalysis produite par le ChainAnalyzer.

    Returns:
        SecurityChain prête à être stockée dans le GraphState.
    """
    # Import tardif pour éviter la dépendance circulaire au module chargement
    from state import FirewallRule, IdsSignature, IpsAction, SecurityChain

    fw_rules: list[FirewallRule] = []
    ids_sigs: list[IdsSignature] = []
    ips_acts: list[IpsAction] = []

    fw_counter = 0
    ids_counter = 0
    ips_counter = 0

    def _fw_id() -> str:
        nonlocal fw_counter
        fw_counter += 1
        return f"FW-{fw_counter:03d}"

    def _ids_id() -> str:
        nonlocal ids_counter
        ids_counter += 1
        return f"IDS-{ids_counter:03d}"

    def _ips_id() -> str:
        nonlocal ips_counter
        ips_counter += 1
        return f"IPS-{ips_counter:03d}"

    is_high_risk = analysis.risk_level.lower() in ("high", "critical")

    # ── 0. Règles LAN par défaut (FW-001, FW-002, FW-003) ────────────────
    # Autorisent le trafic interne Mininet (ICMP, ARP, IPv4 LAN) pour que
    # le failMode="secure" ne bloque pas les pings et la résolution ARP.
    # Priorité 50 : écrasable par les BLOCK (900) et ALLOW spécifiques (100).
    fw_rules.append(FirewallRule(
        id=_fw_id(),   # FW-001
        action="ALLOW",
        direction="both",
        dst_ip="10.0.0.0/24",
        dst_port=None,
        protocol="any",
        priority=50,
        source_transition_id=None,
        comment="Trafic LAN IPv4 interne autorisé par défaut — priorité 50 écrasable par BLOCK (900) et ALLOW spécifiques (100)",
    ))
    fw_rules.append(FirewallRule(
        id=_fw_id(),   # FW-002
        action="ALLOW",
        direction="both",
        dst_ip=None,   # ARP est L2, pas de dst_ip
        dst_port=None,
        protocol="ARP",
        priority=50,
        source_transition_id=None,
        comment="Trafic ARP autorisé — nécessaire pour résolution MAC inter-hosts dans Mininet",
    ))
    fw_rules.append(FirewallRule(
        id=_fw_id(),   # FW-003
        action="ALLOW",
        direction="both",
        dst_ip="10.0.0.0/24",
        dst_port=None,
        protocol="ICMP",
        priority=50,
        source_transition_id=None,
        comment="Trafic ICMP interne autorisé — pour diagnostics ping et traceroute",
    ))

    # ── 1. Règles BLOCK — déduplication par (ip, port, proto) ─────────────
    # Regrouper les transitions par clé (ip, port, proto)
    ip_port_groups: dict[tuple, list] = {}
    for t in analysis.suspicious_transitions:
        key = (t.dst_ip, t.dst_port, t.protocol)
        ip_port_groups.setdefault(key, []).append(t)

    # Un dict ip → fw_id pour commentaires croisés
    ip_to_fw: dict[str, str] = {}

    for (ip, port, proto), group in ip_port_groups.items():
        # SURVEILLANCE SEULE : si TOUTES les transitions du groupe sont
        # "monitoring-only" (flag(s) ⊆ _MONITORING_ONLY_FLAGS et score < 4), on NE
        # crée PAS de BLOCK — la destination sera seulement surveillée (IDS LOW en §2).
        if all(t.flags and set(t.flags) <= _MONITORING_ONLY_FLAGS and t.suspicion_score < 4
               for t in group):
            continue
        fw = _fw_id()
        ip_to_fw[ip] = fw
        trans_ids = [t.transition_id for t in group]
        multi = len(trans_ids) > 1

        comment = (
            f"Trafic suspect vers {ip}:{port}/{proto} "
            f"— transition{'s' if multi else ''}: {', '.join(trans_ids)}"
        )
        if multi:
            comment += " [déduplication multi-transitions]"

        fw_rules.append(FirewallRule(
            id=fw,
            action="BLOCK",
            direction="outbound",
            dst_ip=ip,
            dst_port=port,
            protocol=_norm_proto(proto),
            priority=900,
            source_transition_id=trans_ids[0] if not multi else None,
            comment=comment,
        ))

    # ── 2. Signatures IDS + actions IPS ───────────────────────────────────
    seen_ids: set[tuple[str, str]] = set()  # (pattern_type, dst_ip) déjà créés
    most_critical_ids: str | None = None    # référence pour l'action QUARANTINE

    for t in analysis.suspicious_transitions:
        for flag in _FLAG_ORDER:
            if flag not in t.flags:
                continue
            ids_type = _FLAG_TO_IDS_TYPE[flag]
            dedup = (ids_type, t.dst_ip)
            if dedup in seen_ids:
                continue
            seen_ids.add(dedup)

            sid = _ids_id()
            severity = _IDS_SEVERITY[ids_type]

            # Critères de correspondance selon le type
            criteria: dict = {
                "dst_ip": t.dst_ip,
                "dst_port": t.dst_port,
                "protocol": t.protocol,
            }
            if ids_type == "beaconing":
                criteria["frequency_threshold_per_min"] = 6
            elif ids_type == "data_exfiltration":
                criteria["byte_threshold_outbound"] = 50000
            elif ids_type == "dga_dns":
                criteria["pattern"] = "algorithmic_domain_generation"
            elif ids_type == "suspicious_url":
                criteria["url_path_regex"] = "/(cmd|exec|shell|upload/raw|register)"

            sig_name = f"{ids_type.upper()}_{t.dst_ip.replace('.', '_')}_{t.dst_port}"

            ids_sigs.append(IdsSignature(
                id=sid,
                name=sig_name,
                pattern_type=ids_type,
                match_criteria=criteria,
                severity=severity,
                source_transition_id=t.transition_id,
                comment=f"Détection {ids_type} vers {t.dst_ip}:{t.dst_port} — {t.transition_id}",
            ))

            # Mémoriser la première signature CRITICAL pour l'action QUARANTINE
            if severity == "CRITICAL" and most_critical_ids is None:
                most_critical_ids = sid

            # Action IPS — QUARANTINE si risque élevé + signature critique
            ips_action = _IDS_TO_IPS_ACTION[ids_type]
            if is_high_risk and sid == most_critical_ids:
                ips_action = "QUARANTINE"

            duration: int | None = None
            rate_pps: int | None = None
            if ips_action == "RATE_LIMIT":
                rate_pps = 5
                duration = 300
            elif ips_action == "DROP_SOURCE":
                duration = None  # permanent

            ips_acts.append(IpsAction(
                id=_ips_id(),
                on_signature=sid,
                action=ips_action,
                duration_seconds=duration,
                rate_limit_pps=rate_pps,
                comment=f"Action {ips_action} sur {ids_type} → {t.dst_ip}:{t.dst_port}",
            ))

    # ── 3. Règles ALLOW — 1 par service légitime ──────────────────────────
    for svc in analysis.legitimate_services:
        if not svc.ips:
            continue
        primary_ip = svc.ips[0]
        primary_port = svc.ports[0] if svc.ports else None
        # Préserve le proto connectionless du service (UDP/ICMP) ; sinon ancien
        # comportement TCP/HTTPS par port → A/B byte-identiques (TCP/HTTPS → même ip_proto 6).
        sp = (svc.protocol or "").upper()
        if sp in ("UDP", "ICMP"):
            proto = sp
        else:
            proto = "HTTPS" if primary_port == 443 else "TCP"

        extra = svc.ips[1:]
        comment = f"Service légitime : {svc.name} ({svc.service_type})"
        if extra:
            comment += f" — IPs secondaires: {', '.join(extra)}"

        fw_rules.append(FirewallRule(
            id=_fw_id(),
            action="ALLOW",
            direction="outbound",
            dst_ip=primary_ip,
            dst_port=primary_port,
            protocol=proto,
            priority=100,
            source_transition_id=svc.transition_ids[0] if svc.transition_ids else None,
            comment=comment,
        ))

    # ── 4. Métadonnées ────────────────────────────────────────────────────
    nb_block = sum(1 for r in fw_rules if r.action == "BLOCK")
    nb_allow = sum(1 for r in fw_rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT"))
    risk_level = _norm_risk(analysis.risk_level)

    summary = (
        f"Chaîne générée pour {analysis.app_name} "
        f"(risque: {risk_level}, score: {analysis.global_suspicion_score}/10). "
        f"{nb_block} règle(s) BLOCK, {nb_allow} règle(s) ALLOW, "
        f"{len(ids_sigs)} signature(s) IDS, {len(ips_acts)} action(s) IPS."
    )

    return SecurityChain(
        chain_id=f"chain_{analysis.automate_id}",
        source_automate_id=analysis.automate_id,
        source_app_name=analysis.app_name,
        generated_at=datetime.now(timezone.utc).isoformat(),
        global_risk_level=risk_level,
        firewall_rules=fw_rules,
        ids_signatures=ids_sigs,
        ips_actions=ips_acts,
        deployment_target={
            "ryu_endpoint": "http://localhost:8080",
            "target_switches": ["s0", "s1", "s2"],
            "openflow_version": "1.3",
        },
        generation_summary=summary,
    )


# ---------------------------------------------------------------------------
# Validation d'une SecurityChain
# ---------------------------------------------------------------------------

def validate_chain(chain: "SecurityChain") -> "tuple[SecurityChain, ValidationReport]":
    """Vérifie la cohérence d'une SecurityChain, corrige les redondances et produit un rapport.

    Six catégories de vérifications sont effectuées :
    1. **conflict** — BLOCK et ALLOW pour la même IP destination (ERROR)
    2. **orphan_reference** — IpsAction référençant un IdsSignature inexistant (ERROR)
    3. **redundancy** — Règles FW identiques (WARNING) → la copie est supprimée
    4. **priority_issue** — ALLOW plus prioritaire qu'un BLOCK sur la même IP (WARNING)
    5. **missing_field** — dst_ip None ou match_criteria vide (ERROR)
    6. **best_practice** — Absences de QUARANTINE en mode HIGH, trop de règles, etc. (WARNING)

    Le quality_score est calculé : 100 - 30×ERRORs - 10×WARNINGs (plancher 0).
    is_valid = True si et seulement si nb_errors == 0.

    Args:
        chain: SecurityChain à valider.

    Returns:
        Tuple (SecurityChain corrigée, ValidationReport).
    """
    from state import SecurityChain as SC, ValidationIssue, ValidationReport

    issues: list[ValidationIssue] = []

    # Travailler sur une copie mutable de la liste
    fw_rules = list(chain.firewall_rules)
    ids_ids: set[str] = {s.id for s in chain.ids_signatures}

    # ── Vérification 1 — CONFLICT ─────────────────────────────────────────
    # Regrouper par dst_ip toutes les actions et les IDs de règles associés
    ip_to_actions: dict[str, list[str]] = {}
    ip_to_rule_ids: dict[str, list[str]] = {}
    for r in fw_rules:
        if r.dst_ip:
            ip_to_actions.setdefault(r.dst_ip, []).append(r.action)
            ip_to_rule_ids.setdefault(r.dst_ip, []).append(r.id)

    for ip, actions in ip_to_actions.items():
        has_block = "BLOCK" in actions
        has_allow = bool({"ALLOW", "ALLOW_AND_INSPECT"} & set(actions))
        if has_block and has_allow:
            issues.append(ValidationIssue(
                severity="ERROR",
                category="conflict",
                message=f"Conflit BLOCK/ALLOW sur la même IP destination : {ip}",
                affected_rule_ids=ip_to_rule_ids[ip],
                suggested_fix=(
                    f"Supprimer la règle ALLOW pour {ip} si elle est hostile, "
                    f"ou la règle BLOCK si elle est légitime."
                ),
            ))

    # ── Vérification 2 — ORPHAN_REFERENCE ────────────────────────────────
    for a in chain.ips_actions:
        if a.on_signature not in ids_ids:
            issues.append(ValidationIssue(
                severity="ERROR",
                category="orphan_reference",
                message=(
                    f"IpsAction {a.id} référence une signature inexistante : "
                    f"'{a.on_signature}'"
                ),
                affected_rule_ids=[a.id],
                suggested_fix=(
                    f"Supprimer {a.id} ou créer la signature IDS '{a.on_signature}'."
                ),
            ))

    # ── Vérification 3 — REDUNDANCY ───────────────────────────────────────
    # Clé de déduplication : (action, dst_ip, dst_port, protocol)
    seen_fw: dict[tuple, str] = {}  # clé → id première occurrence
    to_remove: set[str] = set()
    for r in fw_rules:
        key = (r.action, r.dst_ip, r.dst_port, r.protocol)
        if key in seen_fw:
            issues.append(ValidationIssue(
                severity="WARNING",
                category="redundancy",
                message=(
                    f"Règle FW redondante : {r.id} est un doublon exact de "
                    f"{seen_fw[key]}"
                ),
                affected_rule_ids=[r.id, seen_fw[key]],
                suggested_fix=f"Supprimer {r.id} (doublon de {seen_fw[key]}).",
            ))
            to_remove.add(r.id)
        else:
            seen_fw[key] = r.id

    # Suppression effective des doublons
    fw_rules_clean = [r for r in fw_rules if r.id not in to_remove]

    # ── Vérification 4 — PRIORITY ─────────────────────────────────────────
    # Pour chaque IP : min(BLOCK.priority) doit être > max(ALLOW.priority)
    ip_block_prios: dict[str, list[tuple[int, str]]] = {}
    ip_allow_prios: dict[str, list[tuple[int, str]]] = {}
    for r in fw_rules_clean:
        if not r.dst_ip:
            continue
        if r.action == "BLOCK":
            ip_block_prios.setdefault(r.dst_ip, []).append((r.priority, r.id))
        elif r.action in ("ALLOW", "ALLOW_AND_INSPECT"):
            ip_allow_prios.setdefault(r.dst_ip, []).append((r.priority, r.id))

    for ip in set(ip_block_prios) & set(ip_allow_prios):
        min_block = min(p for p, _ in ip_block_prios[ip])
        max_allow = max(p for p, _ in ip_allow_prios[ip])
        if min_block <= max_allow:
            block_ids = [rid for _, rid in ip_block_prios[ip]]
            allow_ids = [rid for _, rid in ip_allow_prios[ip]]
            issues.append(ValidationIssue(
                severity="WARNING",
                category="priority_issue",
                message=(
                    f"Priorité BLOCK insuffisante pour {ip} : "
                    f"min_BLOCK={min_block} ≤ max_ALLOW={max_allow}"
                ),
                affected_rule_ids=block_ids + allow_ids,
                suggested_fix=(
                    f"Augmenter la priorité des règles BLOCK au-dessus de {max_allow}."
                ),
            ))

    # ── Vérification 5 — MISSING_FIELD ────────────────────────────────────
    for r in fw_rules_clean:
        # ARP est un protocole L2 : dst_ip=None est normal et attendu
        if r.dst_ip is None and (r.protocol or "").upper() != "ARP":
            issues.append(ValidationIssue(
                severity="ERROR",
                category="missing_field",
                message=(
                    f"FirewallRule {r.id} : dst_ip est None "
                    f"(utiliser la chaîne 'any' pour un wildcard explicite)"
                ),
                affected_rule_ids=[r.id],
                suggested_fix="Renseigner dst_ip avec une IP cible ou la chaîne 'any'.",
            ))

    for s in chain.ids_signatures:
        if not s.match_criteria:
            issues.append(ValidationIssue(
                severity="ERROR",
                category="missing_field",
                message=f"IdsSignature {s.id} ('{s.name}') : match_criteria est vide",
                affected_rule_ids=[s.id],
                suggested_fix="Ajouter au moins un critère (dst_ip, dst_port, frequency_threshold…).",
            ))

    # ── Vérification 6 — BEST_PRACTICE ────────────────────────────────────
    ips_action_types = {a.action for a in chain.ips_actions}

    if chain.global_risk_level == "HIGH":
        if "QUARANTINE" not in ips_action_types:
            issues.append(ValidationIssue(
                severity="WARNING",
                category="best_practice",
                message=(
                    "Risque global HIGH sans action QUARANTINE : "
                    "la réponse automatique peut être insuffisante"
                ),
                affected_rule_ids=[],
                suggested_fix=(
                    "Ajouter une IpsAction QUARANTINE sur la signature IDS "
                    "la plus critique."
                ),
            ))
        if ips_action_types and ips_action_types <= {"ALERT_ONLY"}:
            issues.append(ValidationIssue(
                severity="WARNING",
                category="best_practice",
                message=(
                    "Toutes les actions IPS sont ALERT_ONLY pour un risque HIGH "
                    "— réaction trop passive face à une menace confirmée"
                ),
                affected_rule_ids=[a.id for a in chain.ips_actions],
                suggested_fix=(
                    "Remplacer au moins une ALERT_ONLY par DROP_SOURCE ou QUARANTINE."
                ),
            ))

    if len(fw_rules_clean) > 50:
        issues.append(ValidationIssue(
            severity="WARNING",
            category="best_practice",
            message=(
                f"Nombre de règles firewall élevé ({len(fw_rules_clean)}) : "
                f"optimisation recommandée"
            ),
            affected_rule_ids=[],
            suggested_fix="Regrouper les IPs de même ASN en CIDRs pour réduire le nombre de règles.",
        ))

    # ── Score qualité ──────────────────────────────────────────────────────
    nb_errors = sum(1 for i in issues if i.severity == "ERROR")
    nb_warnings = sum(1 for i in issues if i.severity == "WARNING")
    score = max(0, 100 - nb_errors * 30 - nb_warnings * 10)
    is_valid = nb_errors == 0

    nb_before = len(chain.firewall_rules)
    nb_after = len(fw_rules_clean)
    duplicates = len(to_remove)

    if is_valid:
        det_summary = (
            f"Chaîne '{chain.chain_id}' validée. "
            f"Score qualité : {score}/100. "
            f"{nb_warnings} avertissement(s). "
            f"{duplicates} doublon(s) supprimé(s)."
        )
    else:
        det_summary = (
            f"Chaîne '{chain.chain_id}' invalide — {nb_errors} erreur(s) critique(s). "
            f"Score qualité : {score}/100. "
            f"{nb_warnings} avertissement(s). "
            f"{duplicates} doublon(s) supprimé(s)."
        )

    corrected = chain.model_copy(update={"firewall_rules": fw_rules_clean})

    report = ValidationReport(
        chain_id=chain.chain_id,
        validated_at=datetime.now(timezone.utc).isoformat(),
        is_valid=is_valid,
        quality_score=score,
        issues=issues,
        stats={
            "nb_rules_before": nb_before,
            "nb_rules_after": nb_after,
            "duplicates_removed": duplicates,
            "nb_ids_signatures": len(chain.ids_signatures),
            "nb_ips_actions": len(chain.ips_actions),
            "nb_errors": nb_errors,
            "nb_warnings": nb_warnings,
        },
        validation_summary=det_summary,
    )

    return corrected, report
