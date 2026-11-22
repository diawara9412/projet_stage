"""
architectures/supervisor/firewall_agent.py — Agent FIREWALL (LLM décisionnaire +
outils de vérification + BOUCLE DE CORRECTION).

Le LLM produit les règles ; les outils (tools/firewall_verification_tools.py) les
vérifient ; la boucle (architectures/supervisor/correction_loop.py) :
  - répare en déterministe ce qui est sûr (retrait hallucinations/champs manquants,
    ajout des LAN par défaut, remontée de priorité BLOCK) ;
  - re-génère (feedback ciblé) ce qui demande un jugement (conflits BLOCK/ALLOW) ;
  - garde le meilleur essai + lève un drapeau à l'épuisement.

CARVE-OUT : la REDONDANCE n'est ni réparée ni régénérée ici (signal scientifique) ;
seul validate_chain la retire en fin de pipeline et le score reste pénalisé.

Garde-fou : sur un 1er passage sans faute de jugement (pokemon/banking), la boucle
s'arrête à la tentative 1 → résultat identique au comportement précédent. Le
fallback déterministe reste le dernier filet si le LLM est injoignable.
"""

from __future__ import annotations

import json
import logging
import re
import warnings

from pydantic import ValidationError

from state import AutomateAnalysis, FirewallRule
from tools.firewall_verification_tools import run_all_checks
from tools.deterministic_repairs import (
    add_missing_lan,
    collect_problem_ids,
    dedup_by,
    drop_items,
    fix_block_priority,
)
from architectures.supervisor.correction_loop import run_with_correction

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL, WORKER_TEMPERATURE  # noqa: F401

logger = logging.getLogger(__name__)

# Tentatives de PARSE par génération (robustesse JSON). Les tentatives de
# CORRECTION (fautes de jugement) sont gérées par la boucle, séparément.
_PARSE_ATTEMPTS = 2
_MAX_CORRECTION_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# PROMPT SYSTÈME (inchangé)
# ---------------------------------------------------------------------------

FIREWALL_LLM_SYSTEM_PROMPT = """Tu es l'agent Firewall d'un système de sécurité réseau SDN (OpenFlow 1.3).

## Ton rôle
À partir d'un diagnostic réseau (transitions suspectes + services légitimes), tu
GÉNÈRES toi-même les règles de pare-feu, par raisonnement. Tu ne te contentes pas
de résumer : c'est TOI qui décides chaque règle.

## Ce que tu reçois
- Une liste de TRANSITIONS SUSPECTES (IP, port, protocole, flags) → à BLOQUER,
  SAUF celles dont les flags sont uniquement ["monitored"] (voir ci-dessous).
- Une liste de SERVICES LÉGITIMES (nom, IP, port) → à AUTORISER.

## Ce que tu dois produire
Pour chaque transition suspecte : UNE règle BLOCK.
EXCEPTION SURVEILLANCE : si les flags d'une transition sont uniquement
["monitored"], ne crée AUCUNE règle firewall pour elle — c'est une destination
SURVEILLÉE (ni bloquée, ni autorisée ; l'IDS s'en charge).
Pour chaque service légitime : UNE règle ALLOW (IP et port du service).
Et TOUJOURS les 3 règles LAN par défaut (trafic interne Mininet) :
  1. ALLOW IPv4 interne   : dst_ip="10.0.0.0/24", protocol="any"
  2. ALLOW ARP            : dst_ip=null,            protocol="ARP"
  3. ALLOW ICMP interne   : dst_ip="10.0.0.0/24", protocol="ICMP"

## Conventions de priorité (IMPÉRATIVES)
- BLOCK (menaces)        : priority=900, direction="outbound"
- ALLOW (services)       : priority=100, direction="outbound"
- LAN par défaut         : priority=50,  direction="both"

## RÈGLES ABSOLUES (anti-hallucination)
- N'invente AUCUNE IP. N'utilise QUE les IPs présentes dans le diagnostic fourni.
- Un BLOCK ne cible QUE des IPs de transitions suspectes.
- Un ALLOW (hors LAN) ne cible QUE des IPs de services légitimes.
- Une seule règle par cible ; jamais BLOCK et ALLOW sur la même IP/port.
- Reprends le protocole tel qu'il est dans le diagnostic (TCP, HTTP, HTTPS, UDP...).

## Schéma JSON EXACT de chaque règle (respecte les noms et les types)
{
  "id": "FW-001",
  "action": "BLOCK" | "ALLOW" | "ALLOW_AND_INSPECT",
  "direction": "inbound" | "outbound" | "both",
  "dst_ip": "x.x.x.x" ou "10.0.0.0/24" ou null,
  "dst_port": entier ou null,
  "protocol": "TCP" | "UDP" | "ICMP" | "HTTP" | "HTTPS" | "any" | "ARP",
  "priority": entier 0-1000,
  "source_transition_id": "tXX" ou null,
  "comment": "explication courte"
}

## Format de réponse OBLIGATOIRE
Réponds UNIQUEMENT avec un objet JSON, SANS texte ni markdown autour :
{
  "firewall_rules": [ { ...règle... }, { ...règle... } ]
}
"""


# ---------------------------------------------------------------------------
# Contexte + parsing (inchangés, + feedback optionnel pour la re-génération)
# ---------------------------------------------------------------------------

def _build_context(analysis: AutomateAnalysis, feedback: str | None = None) -> str:
    susp = "\n".join(
        f"  - transition_id={t.transition_id} ip={t.dst_ip} port={t.dst_port} "
        f"protocol={t.protocol} flags={t.flags}"
        for t in analysis.suspicious_transitions
    ) or "  (aucune)"
    legit = "\n".join(
        f"  - name=\"{s.name}\" ip={s.ips[0] if s.ips else None} "
        f"port={s.ports[0] if s.ports else None} protocol={s.protocol or 'TCP'} "
        f"type={s.service_type}"
        for s in analysis.legitimate_services
    ) or "  (aucun)"
    base = (
        f"Application : {analysis.app_name} (risque global : {analysis.risk_level})\n\n"
        f"TRANSITIONS SUSPECTES (→ BLOCK) :\n{susp}\n\n"
        f"SERVICES LÉGITIMES (→ ALLOW) :\n{legit}\n\n"
        f"Génère le JSON des firewall_rules (BLOCK + ALLOW + 3 LAN par défaut)."
    )
    if feedback:
        base += f"\n\n## CORRECTION DEMANDÉE\n{feedback}"
    return base


def _parse_rules(raw: str) -> list[FirewallRule]:
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        raise ValueError("aucun objet JSON trouvé dans la réponse LLM")
    data = json.loads(m.group())
    raw_rules = data.get("firewall_rules")
    if not isinstance(raw_rules, list):
        raise ValueError("champ 'firewall_rules' absent ou non-liste")
    rules: list[FirewallRule] = []
    for i, rd in enumerate(raw_rules, start=1):
        if not isinstance(rd, dict):
            continue
        if not rd.get("id"):
            rd["id"] = f"FW-{i:03d}"
        if rd.get("dst_port") in ("", "null"):
            rd["dst_port"] = None
        try:
            rules.append(FirewallRule(**rd))  # éléments invalides ignorés (build)
        except ValidationError:
            continue
    return rules


def _reassign_ids(rules: list[FirewallRule]) -> list[FirewallRule]:
    return [r.model_copy(update={"id": f"FW-{i:03d}"}) for i, r in enumerate(rules, start=1)]


# ---------------------------------------------------------------------------
# Callbacks de la boucle de correction
# ---------------------------------------------------------------------------

def _make_generate(analysis: AutomateAnalysis):
    """Fabrique la callback generate(feedback) (1 appel LLM, parse robuste)."""
    if not GROQ_API_KEY:
        return None  # pas de clé → l'appelant ira au fallback

    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_groq import ChatGroq
    from architectures.supervisor.llm_runtime import get_temperature

    llm = ChatGroq(api_key=GROQ_API_KEY, model=WORKER_MODEL,
                   temperature=get_temperature(WORKER_TEMPERATURE))

    def generate(feedback: str | None):
        context = _build_context(analysis, feedback)
        for _ in range(_PARSE_ATTEMPTS):
            try:
                resp = llm.invoke([
                    SystemMessage(content=FIREWALL_LLM_SYSTEM_PROMPT),
                    HumanMessage(content=context),
                ])
                rules = _parse_rules(resp.content.strip())
                if rules:
                    return rules, []
            except Exception as exc:
                logger.warning("Firewall : parse/appel LLM échoué (%s)", exc)
        return None, []

    return generate


def _repair(items, checks):
    """Réparations déterministes firewall (traitement homogène, dédup INCLUSE)."""
    fixes: list[str] = []
    drop = collect_problem_ids(checks["hallucinations"]) | collect_problem_ids(checks["missing_fields"])
    if drop:
        items = drop_items(items, drop)
        fixes.append(f"{len(drop)} règle(s) retirée(s) (hallucination/champ manquant)")
    # Déduplication (la chaîne finale doit être propre — le compte d'origine est
    # conservé dans errors_before_correction).
    items, ndup = dedup_by(items, lambda r: (r.action, r.dst_ip, r.dst_port, (r.protocol or "").upper()))
    if ndup:
        fixes.append(f"{ndup} doublon(s) supprimé(s)")
    items, f1 = add_missing_lan(items)
    items, f2 = fix_block_priority(items)
    return items, fixes + f1 + f2


def _residual(checks):
    """Fautes de jugement firewall = conflits BLOCK/ALLOW (redondance EXCLUE)."""
    return checks["conflicts"]


def _feedback(items, residuals) -> str:
    lignes = "\n".join(f"  - {p['message']}" for p in residuals)
    return ("Ta sortie précédente a des CONFLITS BLOCK/ALLOW sur la même cible :\n"
            f"{lignes}\n"
            "Renvoie la liste COMPLÈTE corrigée : une seule décision par cible "
            "(bloquer OU autoriser, pas les deux). Ne change pas les règles déjà correctes.")


def _agent_score(checks) -> float:
    # Plus haut = meilleur ; on minimise les conflits résiduels.
    return -float(len(checks["conflicts"]))


# ---------------------------------------------------------------------------
# Fallback déterministe + résumé (inchangés)
# ---------------------------------------------------------------------------

def _fallback_deterministic(analysis: AutomateAnalysis) -> list[FirewallRule]:
    from tools.chain_tools import generate_chain_from_analysis
    return list(generate_chain_from_analysis(analysis).firewall_rules)


def _deterministic_summary(analysis: AutomateAnalysis, rules: list[FirewallRule], source: str) -> str:
    nb_block = sum(1 for r in rules if r.action == "BLOCK")
    nb_allow = sum(1 for r in rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT"))
    origine = "générée par le LLM" if source == "llm" else "fallback déterministe"
    return (f"Politique firewall ({origine}) pour {analysis.app_name} : "
            f"{nb_block} BLOCK + {nb_allow} ALLOW (LAN par défaut inclus). "
            "IDS/IPS non produits à ce stade.")


def _build_report(loop: dict, analysis: AutomateAnalysis, rules: list[FirewallRule]) -> dict:
    """Construit le rapport de vérification (schéma compatible + champs boucle)."""
    checks = loop["checks"]
    nb_block = sum(1 for r in rules if r.action == "BLOCK")
    nb_allow = sum(1 for r in rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT"))
    nb_lan = sum(1 for r in rules if (r.protocol or "").upper() == "ARP" or r.dst_ip == "10.0.0.0/24")
    msgs = lambda key: [p["message"] for p in checks.get(key, [])]
    # Compteurs d'erreurs LLM AVANT correction (dict générique + noms en clair)
    eb = loop.get("errors_before_correction") or {}
    return {
        "source": "llm",
        "attempts": loop["attempts"],
        "exhausted": loop["exhausted"],
        "deterministic_fixes": loop["deterministic_fixes"],
        "residual_problems": loop["residual_problems"],
        "rules_kept": len(rules),
        "nb_block": nb_block, "nb_allow": nb_allow, "nb_lan": nb_lan,
        # ── État APRÈS correction (chaîne finale propre) ───────────────────
        "hallucinations": msgs("hallucinations"),
        "conflicts": msgs("conflicts"),
        "redundancies": msgs("redundancies"),
        "missing_fields": msgs("missing_fields"),
        "build_errors": [],
        "lan_problems": msgs("lan_problems"),
        # ── Trace des erreurs LLM AVANT correction (n'affecte pas le score) ──
        "errors_before_correction": eb,
        "errors_before_correction_detail": loop.get("errors_before_correction_detail", {}),
        "doublons_avant_correction": eb.get("redundancies", 0),
        "hallucinations_avant_correction": eb.get("hallucinations", 0),
        "conflits_avant_correction": eb.get("conflicts", 0),
        "champs_manquants_avant_correction": eb.get("missing_fields", 0),
        "lan_manquantes_avant_correction": eb.get("lan_problems", 0),
        "total_erreurs_llm_avant_correction": sum(eb.values()),
    }


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def firewall_node(state) -> dict:
    """Nœud Firewall : LLM décide → outils vérifient → boucle corrige → fallback."""
    logger.info("═══ Firewall (LLM + boucle de correction) : démarrage ═══")

    if state.automate_analysis is None:
        logger.error("Firewall : automate_analysis vide — impossible de générer")
        return {}
    if state.firewall_rules is not None:
        logger.info("Firewall : règles déjà produites — passage de la main")
        return {}

    analysis = state.automate_analysis
    generate = _make_generate(analysis)

    loop = None
    if generate is not None:
        loop = run_with_correction(
            generate=generate,
            verify=lambda items: run_all_checks(items, analysis),
            deterministic_repair=_repair,
            residual_judgment=_residual,
            build_feedback=_feedback,
            agent_score=_agent_score,
            label="Firewall",
            max_attempts=_MAX_CORRECTION_ATTEMPTS,
        )

    # ── Roue de secours si le LLM est injoignable / illisible ───────────────
    if loop is None:
        try:
            rules = _fallback_deterministic(analysis)
            report = {
                "source": "fallback_deterministic", "attempts": 0, "exhausted": False,
                "deterministic_fixes": [], "residual_problems": [],
                "rules_kept": len(rules),
                "nb_block": sum(1 for r in rules if r.action == "BLOCK"),
                "nb_allow": sum(1 for r in rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT")),
                "errors_before_correction": {},
                "errors_before_correction_detail": {},
                "total_erreurs_llm_avant_correction": 0,
            }
            logger.warning("Firewall : %d règle(s) par FALLBACK déterministe", len(rules))
        except Exception as exc:
            logger.error("Firewall : fallback aussi échoué : %s", exc, exc_info=True)
            return {}
    else:
        rules = _reassign_ids(loop["items"])
        report = _build_report(loop, analysis, rules)
        logger.info("Firewall : %d règle(s) gardée(s) en %d tentative(s) (épuisé=%s, "
                    "fixes=%d, résidus=%d)", len(rules), report["attempts"],
                    report["exhausted"], len(report["deterministic_fixes"]),
                    len(report["residual_problems"]))

    summary = _deterministic_summary(analysis, rules, report.get("source", "llm"))
    logger.info("═══ Firewall : terminé (source=%s) ═══", report.get("source"))
    return {
        "firewall_rules": rules,
        "firewall_summary": summary,
        "firewall_verification_report": report,
    }
