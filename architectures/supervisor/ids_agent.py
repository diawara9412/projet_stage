"""
architectures/supervisor/ids_agent.py — Agent IDS (LLM décisionnaire + outils +
BOUCLE DE CORRECTION).

Le LLM produit les signatures ; les outils (tools/ids_verification_tools.py) les
vérifient ; la boucle :
  - répare en déterministe (retrait des signatures hallucinées / à champs manquants) ;
  - re-génère (feedback ciblé) si une menace n'est plus couverte (couverture) ;
  - garde le meilleur essai + drapeau à l'épuisement.

CARVE-OUT : la REDONDANCE n'est ni réparée ni régénérée (signal scientifique).
IDs normalisés IDS-001… EN FIN (critique pour les références on_signature de l'IPS).
Garde-fou : 1er passage sans faute de jugement → tentative 1 → identique à avant.
Fallback déterministe conservé si LLM injoignable.
"""

from __future__ import annotations

import json
import logging
import re
import warnings

from pydantic import ValidationError

from state import AutomateAnalysis, IdsSignature
from tools.ids_verification_tools import run_all_checks
from tools.deterministic_repairs import collect_problem_ids, dedup_by, drop_items
from architectures.supervisor.correction_loop import run_with_correction

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL, WORKER_TEMPERATURE  # noqa: F401

logger = logging.getLogger(__name__)

_PARSE_ATTEMPTS = 2
_MAX_CORRECTION_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# PROMPT SYSTÈME (inchangé)
# ---------------------------------------------------------------------------

IDS_LLM_SYSTEM_PROMPT = """Tu es l'agent IDS d'un système de sécurité réseau SDN (détection d'intrusion).

## Ton rôle
À partir d'un diagnostic réseau (transitions suspectes avec leurs flags), tu
GÉNÈRES toi-même les signatures de détection, par raisonnement.

## Correspondance flag → signature (IMPÉRATIVE)
  - tor_exit_node     → pattern_type="tor_communication", severity="CRITICAL"
  - beaconing         → pattern_type="beaconing",         severity="HIGH"
  - data_exfiltration → pattern_type="data_exfiltration", severity="CRITICAL"
  - dga_domain        → pattern_type="dga_dns",           severity="HIGH"
  - suspicious_path   → pattern_type="suspicious_url",    severity="MEDIUM"
  - monitored         → pattern_type="monitored",         severity="LOW"
Les autres flags (ex. bulletproof_hosting) ne donnent PAS de signature : ignore-les.
Une seule signature par couple (pattern_type, IP) : pas de doublon.

## match_criteria attendu
Toujours : {"dst_ip": <IP>, "dst_port": <port>, "protocol": <protocole>}
Et selon le type, ajoute :
  - beaconing         : "frequency_threshold_per_min": 6
  - data_exfiltration : "byte_threshold_outbound": 50000
  - dga_dns           : "pattern": "algorithmic_domain_generation"
  - suspicious_url    : "url_path_regex": "/(cmd|exec|shell|upload/raw|register)"

## RÈGLES ABSOLUES (anti-hallucination)
- N'invente AUCUNE IP/port : n'utilise QUE ceux des transitions suspectes fournies.
- Couvre CHAQUE transition suspecte par au moins une signature.
- "name" suit le format : TYPE_EN_MAJ + "_" + IP_avec_underscores + "_" + port
  (ex. TOR_COMMUNICATION_185_220_101_47_9001).

## Schéma JSON EXACT de chaque signature
{
  "id": "IDS-001",
  "name": "TOR_COMMUNICATION_185_220_101_47_9001",
  "pattern_type": "tor_communication" | "beaconing" | "data_exfiltration" | "dga_dns" | "suspicious_url" | "port_scan" | "syn_flood" | "monitored",
  "match_criteria": { "dst_ip": "...", "dst_port": 0, "protocol": "..." },
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "source_transition_id": "tXX" ou null,
  "comment": "explication courte"
}

## Format de réponse OBLIGATOIRE
Réponds UNIQUEMENT avec un objet JSON, SANS texte ni markdown autour :
{
  "ids_signatures": [ { ...signature... }, { ...signature... } ]
}
"""


# ---------------------------------------------------------------------------
# Contexte + parsing
# ---------------------------------------------------------------------------

def _build_context(analysis: AutomateAnalysis, blocked_ips: list[str], feedback: str | None = None) -> str:
    susp = "\n".join(
        f"  - transition_id={t.transition_id} ip={t.dst_ip} port={t.dst_port} "
        f"protocol={t.protocol} flags={t.flags}"
        for t in analysis.suspicious_transitions
    ) or "  (aucune)"
    blocked = ", ".join(blocked_ips) or "(aucune)"
    base = (
        f"Application : {analysis.app_name} (risque global : {analysis.risk_level})\n\n"
        f"TRANSITIONS SUSPECTES (génère les signatures correspondantes) :\n{susp}\n\n"
        f"Pour information, IPs déjà bloquées par le firewall : {blocked}\n\n"
        f"Génère le JSON des ids_signatures (une par flag pertinent, sans doublon)."
    )
    if feedback:
        base += f"\n\n## CORRECTION DEMANDÉE\n{feedback}"
    return base


def _parse_signatures(raw: str) -> list[IdsSignature]:
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        raise ValueError("aucun objet JSON trouvé dans la réponse LLM")
    data = json.loads(m.group())
    raw_sigs = data.get("ids_signatures")
    if not isinstance(raw_sigs, list):
        raise ValueError("champ 'ids_signatures' absent ou non-liste")
    sigs: list[IdsSignature] = []
    for i, sd in enumerate(raw_sigs, start=1):
        if not isinstance(sd, dict):
            continue
        if not sd.get("id"):
            sd["id"] = f"IDS-{i:03d}"
        try:
            sigs.append(IdsSignature(**sd))
        except ValidationError:
            continue
    return sigs


def _normalize_ids(signatures: list[IdsSignature]) -> list[IdsSignature]:
    """Normalise IDS-001, IDS-002… (CRITIQUE pour les références on_signature de l'IPS)."""
    return [s.model_copy(update={"id": f"IDS-{i:03d}"}) for i, s in enumerate(signatures, start=1)]


# ---------------------------------------------------------------------------
# Callbacks de la boucle
# ---------------------------------------------------------------------------

def _make_generate(analysis: AutomateAnalysis, blocked_ips: list[str]):
    if not GROQ_API_KEY:
        return None
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_groq import ChatGroq
    from architectures.supervisor.llm_runtime import get_temperature

    llm = ChatGroq(api_key=GROQ_API_KEY, model=WORKER_MODEL,
                   temperature=get_temperature(WORKER_TEMPERATURE))

    def generate(feedback: str | None):
        context = _build_context(analysis, blocked_ips, feedback)
        for _ in range(_PARSE_ATTEMPTS):
            try:
                resp = llm.invoke([
                    SystemMessage(content=IDS_LLM_SYSTEM_PROMPT),
                    HumanMessage(content=context),
                ])
                sigs = _parse_signatures(resp.content.strip())
                if sigs:
                    return sigs, []
            except Exception as exc:
                logger.warning("IDS : parse/appel LLM échoué (%s)", exc)
        return None, []

    return generate


def _repair(items, checks):
    """Réparations déterministes IDS (traitement homogène, dédup INCLUSE)."""
    fixes: list[str] = []
    drop = collect_problem_ids(checks["hallucinations"]) | collect_problem_ids(checks["missing_fields"])
    if drop:
        items = drop_items(items, drop)
        fixes.append(f"{len(drop)} signature(s) retirée(s) (hallucination/champ manquant)")
    items, ndup = dedup_by(items, lambda s: (s.pattern_type, (s.match_criteria or {}).get("dst_ip")))
    if ndup:
        fixes.append(f"{ndup} doublon(s) supprimé(s)")
    return items, fixes


def _residual(checks):
    """Fautes de jugement IDS = couverture manquante (redondance EXCLUE)."""
    return checks["coverage"]


def _feedback(items, residuals) -> str:
    lignes = "\n".join(f"  - {p['message']}" for p in residuals)
    return ("Des transitions suspectes ne sont PLUS surveillées (signatures invalides "
            f"retirées) :\n{lignes}\n"
            "Renvoie la liste COMPLÈTE en AJOUTANT les signatures manquantes pour ces "
            "cibles, avec des IPs EXACTES du diagnostic (pas d'IP malformée). Conserve "
            "les signatures déjà correctes.")


def _agent_score(checks) -> float:
    return -float(len(checks["coverage"]))


# ---------------------------------------------------------------------------
# Fallback + résumé + rapport
# ---------------------------------------------------------------------------

def _fallback_deterministic(analysis: AutomateAnalysis) -> list[IdsSignature]:
    from tools.chain_tools import generate_chain_from_analysis
    return list(generate_chain_from_analysis(analysis).ids_signatures)


def _deterministic_summary(analysis: AutomateAnalysis, sigs: list[IdsSignature], source: str) -> str:
    by_sev: dict[str, int] = {}
    for s in sigs:
        by_sev[s.severity] = by_sev.get(s.severity, 0) + 1
    sev = ", ".join(f"{n} {k}" for k, n in by_sev.items()) or "aucune"
    origine = "générées par le LLM" if source == "llm" else "fallback déterministe"
    return (f"Couverture IDS ({origine}) pour {analysis.app_name} : "
            f"{len(sigs)} signature(s) ({sev}). IPS non produit à ce stade.")


def _build_report(loop: dict, sigs: list[IdsSignature]) -> dict:
    checks = loop["checks"]
    by_type: dict[str, int] = {}
    for s in sigs:
        by_type[s.pattern_type] = by_type.get(s.pattern_type, 0) + 1
    msgs = lambda key: [p["message"] for p in checks.get(key, [])]
    eb = loop.get("errors_before_correction") or {}
    return {
        "source": "llm",
        "attempts": loop["attempts"],
        "exhausted": loop["exhausted"],
        "deterministic_fixes": loop["deterministic_fixes"],
        "residual_problems": loop["residual_problems"],
        "sigs_kept": len(sigs),
        "by_pattern_type": by_type,
        # ── État APRÈS correction ──────────────────────────────────────────
        "hallucinations": msgs("hallucinations"),
        "redundancies": msgs("redundancies"),
        "missing_fields": msgs("missing_fields"),
        "build_errors": [],
        "coverage": msgs("coverage"),
        # ── Trace des erreurs LLM AVANT correction (n'affecte pas le score) ──
        "errors_before_correction": eb,
        "errors_before_correction_detail": loop.get("errors_before_correction_detail", {}),
        "doublons_avant_correction": eb.get("redundancies", 0),
        "hallucinations_avant_correction": eb.get("hallucinations", 0),
        "champs_manquants_avant_correction": eb.get("missing_fields", 0),
        "couverture_avant_correction": eb.get("coverage", 0),
        "total_erreurs_llm_avant_correction": sum(eb.values()),
    }


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def ids_node(state) -> dict:
    """Nœud IDS : LLM décide → outils vérifient → boucle corrige → fallback."""
    logger.info("═══ IDS (LLM + boucle de correction) : démarrage ═══")

    if state.automate_analysis is None:
        logger.error("IDS : automate_analysis vide — impossible de générer")
        return {}
    if state.ids_signatures is not None:
        logger.info("IDS : signatures déjà produites — passage de la main")
        return {}

    analysis = state.automate_analysis
    blocked_ips = []
    if state.firewall_rules:
        blocked_ips = [r.dst_ip for r in state.firewall_rules if r.action == "BLOCK" and r.dst_ip]

    generate = _make_generate(analysis, blocked_ips)

    loop = None
    if generate is not None:
        loop = run_with_correction(
            generate=generate,
            verify=lambda items: run_all_checks(items, analysis),
            deterministic_repair=_repair,
            residual_judgment=_residual,
            build_feedback=_feedback,
            agent_score=_agent_score,
            label="IDS",
            max_attempts=_MAX_CORRECTION_ATTEMPTS,
        )

    if loop is None:
        try:
            sigs = _normalize_ids(_fallback_deterministic(analysis))
            report = {
                "source": "fallback_deterministic", "attempts": 0, "exhausted": False,
                "deterministic_fixes": [], "residual_problems": [], "sigs_kept": len(sigs),
                "errors_before_correction": {}, "errors_before_correction_detail": {},
                "total_erreurs_llm_avant_correction": 0,
            }
            logger.warning("IDS : %d signature(s) par FALLBACK déterministe", len(sigs))
        except Exception as exc:
            logger.error("IDS : fallback aussi échoué : %s", exc, exc_info=True)
            return {}
    else:
        sigs = _normalize_ids(loop["items"])
        report = _build_report(loop, sigs)
        logger.info("IDS : %d signature(s) en %d tentative(s) (épuisé=%s, fixes=%d, résidus=%d)",
                    len(sigs), report["attempts"], report["exhausted"],
                    len(report["deterministic_fixes"]), len(report["residual_problems"]))

    summary = _deterministic_summary(analysis, sigs, report.get("source", "llm"))
    logger.info("═══ IDS : terminé (source=%s) ═══", report.get("source"))
    return {
        "ids_signatures": sigs,
        "ids_summary": summary,
        "ids_verification_report": report,
    }
