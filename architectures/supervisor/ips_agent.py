"""
architectures/supervisor/ips_agent.py — Agent IPS (LLM décisionnaire + outils +
BOUCLE DE CORRECTION).

Le LLM produit les actions ; les outils (tools/ips_verification_tools.py) les
vérifient ; la boucle :
  - répare en déterministe (retrait des orphelins / actions invalides / champs
    manquants) ;
  - re-génère (feedback ciblé) si une signature n'est plus armée (couverture) ;
  - garde le meilleur essai + drapeau à l'épuisement.

PARTICULARITÉ : chaque ``on_signature`` doit référencer un IdsSignature.id réel
(liste fermée fournie au prompt) ; ``check_orphan_references`` est l'outil critique.
CARVE-OUT : la REDONDANCE n'est ni réparée ni régénérée (signal scientifique).
Garde-fou : 1er passage sans faute de jugement → tentative 1 → identique à avant.
Fallback déterministe conservé si LLM injoignable.
"""

from __future__ import annotations

import json
import logging
import re
import warnings

from pydantic import ValidationError

from state import AutomateAnalysis, IdsSignature, IpsAction
from tools.ips_verification_tools import run_all_checks
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

IPS_LLM_SYSTEM_PROMPT = """Tu es l'agent IPS d'un système de sécurité réseau SDN (prévention d'intrusion).

## Ton rôle
À partir des SIGNATURES IDS disponibles, tu GÉNÈRES les actions de réponse
automatique. Une action par signature : c'est TOI qui décides quelle réponse armer.

## Contrainte ABSOLUE sur les références (la plus importante)
Le message te fournit la LISTE EXACTE des signatures IDS disponibles (id,
pattern_type, severity). Le champ ``on_signature`` de CHAQUE action DOIT être l'un
de ces ids EXACTEMENT. Tu n'as PAS le droit d'inventer un id de signature.

## Logique severity → action (choisis DANS ces bornes)
  - severity CRITICAL → "DROP_SOURCE" (ou "QUARANTINE" si menace à isoler)
  - severity HIGH     → "DROP_SOURCE" ou "RATE_LIMIT"
  - severity MEDIUM   → "ALERT_ONLY"
  - severity LOW      → "ALERT_ONLY"
N'utilise QUE ces 4 actions : DROP_SOURCE, RATE_LIMIT, QUARANTINE, ALERT_ONLY.

## Conventions de champs
  - Si action="RATE_LIMIT" : renseigne "rate_limit_pps" (ex. 5) et "duration_seconds" (ex. 300).
  - Si action="DROP_SOURCE" : "duration_seconds"=null (permanent), "rate_limit_pps"=null.
  - Sinon : "duration_seconds" et "rate_limit_pps" peuvent être null.
Couvre CHAQUE signature fournie par au moins une action (aucune signature orpheline).

## Schéma JSON EXACT de chaque action
{
  "id": "IPS-001",
  "on_signature": "IDS-001",
  "action": "DROP_SOURCE" | "RATE_LIMIT" | "QUARANTINE" | "ALERT_ONLY",
  "duration_seconds": entier ou null,
  "rate_limit_pps": entier ou null,
  "comment": "explication courte"
}

## Format de réponse OBLIGATOIRE
Réponds UNIQUEMENT avec un objet JSON, SANS texte ni markdown autour :
{
  "ips_actions": [ { ...action... }, { ...action... } ]
}
"""


# ---------------------------------------------------------------------------
# Contexte + parsing
# ---------------------------------------------------------------------------

def _build_context(analysis: AutomateAnalysis, ids_signatures: list[IdsSignature],
                   feedback: str | None = None) -> str:
    sigs = "\n".join(
        f"  - id={s.id} pattern_type={s.pattern_type} severity={s.severity} "
        f"cible={(s.match_criteria or {}).get('dst_ip')}"
        for s in ids_signatures
    ) or "  (aucune)"
    base = (
        f"Application : {analysis.app_name} (risque global : {analysis.risk_level})\n\n"
        f"SIGNATURES IDS DISPONIBLES (tu ne peux référencer QUE ces ids) :\n{sigs}\n\n"
        f"Génère le JSON des ips_actions : UNE action par signature ci-dessus, "
        f"avec on_signature == l'id de la signature concernée."
    )
    if feedback:
        base += f"\n\n## CORRECTION DEMANDÉE\n{feedback}"
    return base


def _parse_actions(raw: str) -> list[IpsAction]:
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        raise ValueError("aucun objet JSON trouvé dans la réponse LLM")
    data = json.loads(m.group())
    raw_acts = data.get("ips_actions")
    if not isinstance(raw_acts, list):
        raise ValueError("champ 'ips_actions' absent ou non-liste")
    acts: list[IpsAction] = []
    for i, ad in enumerate(raw_acts, start=1):
        if not isinstance(ad, dict):
            continue
        if not ad.get("id"):
            ad["id"] = f"IPS-{i:03d}"
        try:
            acts.append(IpsAction(**ad))
        except ValidationError:
            continue
    return acts


def _renumber(actions: list[IpsAction]) -> list[IpsAction]:
    return [a.model_copy(update={"id": f"IPS-{i:03d}"}) for i, a in enumerate(actions, start=1)]


# ---------------------------------------------------------------------------
# Callbacks de la boucle
# ---------------------------------------------------------------------------

def _make_generate(analysis: AutomateAnalysis, ids_signatures: list[IdsSignature]):
    if not GROQ_API_KEY:
        return None
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_groq import ChatGroq
    from architectures.supervisor.llm_runtime import get_temperature

    llm = ChatGroq(api_key=GROQ_API_KEY, model=WORKER_MODEL,
                   temperature=get_temperature(WORKER_TEMPERATURE))

    def generate(feedback: str | None):
        context = _build_context(analysis, ids_signatures, feedback)
        for _ in range(_PARSE_ATTEMPTS):
            try:
                resp = llm.invoke([
                    SystemMessage(content=IPS_LLM_SYSTEM_PROMPT),
                    HumanMessage(content=context),
                ])
                acts = _parse_actions(resp.content.strip())
                if acts:
                    return acts, []
            except Exception as exc:
                logger.warning("IPS : parse/appel LLM échoué (%s)", exc)
        return None, []

    return generate


def _make_repair(ids_signatures: list[IdsSignature]):
    """Réparations déterministes IPS (drop orphelins/invalides/champs ; PAS de dédup)."""
    def _repair(items, checks):
        fixes: list[str] = []
        drop = (collect_problem_ids(checks["orphans"])
                | collect_problem_ids(checks["invalid_actions"])
                | collect_problem_ids(checks["missing_fields"]))
        if drop:
            items = drop_items(items, drop)
            fixes.append(f"{len(drop)} action(s) retirée(s) (orphelin/action invalide/champ)")
        items, ndup = dedup_by(items, lambda a: (a.on_signature, a.action))
        if ndup:
            fixes.append(f"{ndup} doublon(s) supprimé(s)")
        return items, fixes
    return _repair


def _residual(checks):
    """Fautes de jugement IPS = couverture manquante (redondance EXCLUE)."""
    return checks["coverage"]


def _feedback(items, residuals) -> str:
    lignes = "\n".join(f"  - {p['message']}" for p in residuals)
    return ("Des signatures IDS ne sont PLUS armées (actions invalides/orphelines "
            f"retirées) :\n{lignes}\n"
            "Renvoie la liste COMPLÈTE en AJOUTANT une action pour chaque signature "
            "non armée, avec on_signature parmi les ids fournis UNIQUEMENT. Conserve "
            "les actions déjà correctes.")


def _agent_score(checks) -> float:
    return -float(len(checks["coverage"]))


# ---------------------------------------------------------------------------
# Fallback + résumé + rapport
# ---------------------------------------------------------------------------

def _fallback_deterministic(analysis: AutomateAnalysis, ids_signatures: list[IdsSignature]) -> list[IpsAction]:
    from tools.chain_tools import generate_chain_from_analysis
    raw = list(generate_chain_from_analysis(analysis).ips_actions)
    valid_ids = {s.id for s in ids_signatures}
    return [a for a in raw if a.on_signature in valid_ids]


def _deterministic_summary(analysis: AutomateAnalysis, acts: list[IpsAction], source: str) -> str:
    by_action: dict[str, int] = {}
    for a in acts:
        by_action[a.action] = by_action.get(a.action, 0) + 1
    rep = ", ".join(f"{n}×{k}" for k, n in by_action.items()) or "aucune"
    origine = "générées par le LLM" if source == "llm" else "fallback déterministe"
    return (f"Réponses IPS ({origine}) pour {analysis.app_name} : "
            f"{len(acts)} action(s) ({rep}), chacune armée par une signature existante.")


def _build_report(loop: dict, acts: list[IpsAction]) -> dict:
    checks = loop["checks"]
    by_action: dict[str, int] = {}
    for a in acts:
        by_action[a.action] = by_action.get(a.action, 0) + 1
    msgs = lambda key: [p["message"] for p in checks.get(key, [])]
    eb = loop.get("errors_before_correction") or {}
    return {
        "source": "llm",
        "attempts": loop["attempts"],
        "exhausted": loop["exhausted"],
        "deterministic_fixes": loop["deterministic_fixes"],
        "residual_problems": loop["residual_problems"],
        "acts_kept": len(acts),
        "by_action": by_action,
        # ── État APRÈS correction ──────────────────────────────────────────
        "orphans": msgs("orphans"),
        "redundancies": msgs("redundancies"),
        "missing_fields": msgs("missing_fields"),
        "invalid_actions": msgs("invalid_actions"),
        "build_errors": [],
        "coverage": msgs("coverage"),
        # ── Trace des erreurs LLM AVANT correction (n'affecte pas le score) ──
        "errors_before_correction": eb,
        "errors_before_correction_detail": loop.get("errors_before_correction_detail", {}),
        "orphelins_avant_correction": eb.get("orphans", 0),
        "doublons_avant_correction": eb.get("redundancies", 0),
        "actions_invalides_avant_correction": eb.get("invalid_actions", 0),
        "champs_manquants_avant_correction": eb.get("missing_fields", 0),
        "couverture_avant_correction": eb.get("coverage", 0),
        "total_erreurs_llm_avant_correction": sum(eb.values()),
    }


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def ips_node(state) -> dict:
    """Nœud IPS : LLM décide → outils vérifient → boucle corrige → fallback."""
    logger.info("═══ IPS (LLM + boucle de correction) : démarrage ═══")

    if state.automate_analysis is None:
        logger.error("IPS : automate_analysis vide — impossible de générer")
        return {}
    if state.ids_signatures is None:
        logger.error("IPS : ids_signatures est None — l'IDS doit tourner avant l'IPS")
        return {}
    if state.ips_actions is not None:
        logger.info("IPS : actions déjà produites — passage de la main")
        return {}

    analysis = state.automate_analysis
    ids_signatures = state.ids_signatures
    generate = _make_generate(analysis, ids_signatures)

    loop = None
    if generate is not None:
        loop = run_with_correction(
            generate=generate,
            verify=lambda items: run_all_checks(items, ids_signatures),
            deterministic_repair=_make_repair(ids_signatures),
            residual_judgment=_residual,
            build_feedback=_feedback,
            agent_score=_agent_score,
            label="IPS",
            max_attempts=_MAX_CORRECTION_ATTEMPTS,
        )

    if loop is None:
        try:
            acts = _renumber(_fallback_deterministic(analysis, ids_signatures))
            report = {
                "source": "fallback_deterministic", "attempts": 0, "exhausted": False,
                "deterministic_fixes": [], "residual_problems": [], "acts_kept": len(acts),
                "errors_before_correction": {}, "errors_before_correction_detail": {},
                "total_erreurs_llm_avant_correction": 0,
            }
            logger.warning("IPS : %d action(s) par FALLBACK déterministe", len(acts))
        except Exception as exc:
            logger.error("IPS : fallback aussi échoué : %s", exc, exc_info=True)
            return {}
    else:
        acts = _renumber(loop["items"])
        report = _build_report(loop, acts)
        logger.info("IPS : %d action(s) en %d tentative(s) (épuisé=%s, fixes=%d, résidus=%d)",
                    len(acts), report["attempts"], report["exhausted"],
                    len(report["deterministic_fixes"]), len(report["residual_problems"]))

    summary = _deterministic_summary(analysis, acts, report.get("source", "llm"))
    logger.info("═══ IPS : terminé (source=%s) ═══", report.get("source"))
    return {
        "ips_actions": acts,
        "ips_summary": summary,
        "ips_verification_report": report,
    }
