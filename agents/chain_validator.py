"""
agents/chain_validator.py — Agent ChainValidator du système Phase 2.

Lit la SecurityChain du GraphState, vérifie sa cohérence (conflits, orphelins,
redondances, priorités, champs manquants, bonnes pratiques), corrige les
redondances et produit un ValidationReport.

Flux de traitement
------------------
1. Garde : pas de SecurityChain → retourne {} immédiatement.
2. Garde : ValidationReport déjà présent → idempotent, retourne {}.
3. Validation déterministe via ``validate_chain`` : corrections + rapport.
4. Enrichissement LLM optionnel : validation_summary narratif en français.
5. Retourne ``{"security_chain": chaîne_corrigée, "validation_report": rapport}``.
"""

import json
import logging
import re
import warnings

from state import GraphState, SecurityChain, ValidationReport
from tools.chain_tools import validate_chain

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

CHAIN_VALIDATOR_SYSTEM_PROMPT = """Tu es l'agent ChainValidator d'un système de sécurité réseau SDN basé sur LangGraph.

## Ta mission

Produire un résumé narratif clair d'un rapport de validation de chaîne de sécurité.
Le rapport contient des problèmes détectés (ERRORs, WARNINGs) et un score qualité.

## Ce que tu reçois

Un résumé du rapport de validation déterministe : score, problèmes détectés,
corrections appliquées, et le contexte de la chaîne (application, niveau de risque).

## Ce que tu dois produire

Un objet JSON STRICT avec exactement un champ :

```json
{
  "validation_summary": "Résumé narratif de 3 à 5 phrases en français. Mention : le score qualité, les erreurs critiques détectées (si présentes), les corrections appliquées, et une appréciation globale de la chaîne."
}
```

## Règles

- Cite les IDs des règles problématiques (FW-001, IDS-002, etc.) quand pertinent.
- Pour un score ≥ 90 : appréciation positive, chaîne prête au déploiement.
- Pour un score 60–89 : avertissements présents mais chaîne fonctionnelle.
- Pour un score < 60 : problèmes critiques, déploiement déconseillé avant correction.
- Réponds UNIQUEMENT avec le JSON, sans markdown ni texte autour.
"""

# ---------------------------------------------------------------------------
# Enrichissement LLM
# ---------------------------------------------------------------------------

def _enrich_with_llm(chain: SecurityChain, report: ValidationReport) -> ValidationReport:
    """Remplace le validation_summary déterministe par un résumé narratif LLM."""
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_groq import ChatGroq

        llm = ChatGroq(
            api_key=GROQ_API_KEY,
            model=WORKER_MODEL,
            temperature=0.1,
        )

        errors = [i for i in report.issues if i.severity == "ERROR"]
        warnings_ = [i for i in report.issues if i.severity == "WARNING"]

        errors_str = "\n".join(
            f"  - [{i.category}] {i.message} (règles: {i.affected_rule_ids})"
            for i in errors
        ) or "  (aucune erreur)"

        warnings_str = "\n".join(
            f"  - [{i.category}] {i.message}"
            for i in warnings_
        ) or "  (aucun avertissement)"

        context = f"""Chaîne validée : {chain.chain_id} — Application : {chain.source_app_name}
Risque global : {chain.global_risk_level}
Score qualité : {report.quality_score}/100 — is_valid : {report.is_valid}
Règles FW avant/après : {report.stats.get('nb_rules_before')}/{report.stats.get('nb_rules_after')} ({report.stats.get('duplicates_removed', 0)} doublon(s) supprimé(s))

Erreurs critiques ({len(errors)}) :
{errors_str}

Avertissements ({len(warnings_)}) :
{warnings_str}

Produis le JSON demandé avec un validation_summary narratif en français."""

        response = llm.invoke([
            SystemMessage(content=CHAIN_VALIDATOR_SYSTEM_PROMPT),
            HumanMessage(content=context),
        ])

        raw = response.content.strip()
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if not m:
            logger.warning("LLM n'a pas retourné de JSON valide — résumé déterministe conservé")
            return report

        data = json.loads(m.group())
        llm_summary = data.get("validation_summary")
        if llm_summary:
            return report.model_copy(update={"validation_summary": llm_summary})

    except Exception as exc:
        logger.warning("Enrichissement LLM échoué : %s — résumé déterministe conservé", exc)

    return report


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def chain_validator_node(state: GraphState) -> dict:
    """Nœud ChainValidator du graphe LangGraph Phase 2.

    Valide la SecurityChain du GraphState, corrige les redondances et produit
    un ValidationReport.  Idempotent si le rapport existe déjà.

    Args:
        state: État courant du graphe.

    Returns:
        dict: ``{"security_chain": chaîne_corrigée, "validation_report": rapport}``
              si réussi, ``{}`` sinon.
    """
    logger.info("═══ ChainValidator : démarrage ═══")

    # Garde 1 : pas de chaîne à valider
    if state.security_chain is None:
        logger.error("ChainValidator : state.security_chain est vide — impossible de valider")
        return {}

    # Garde 2 : idempotence
    if state.validation_report is not None:
        logger.info(
            "Rapport '%s' déjà présent — passage de la main",
            state.validation_report.chain_id,
        )
        return {}

    chain = state.security_chain

    try:
        # Validation déterministe
        corrected_chain, report = validate_chain(chain)
        logger.info(
            "Validation : score=%d/100, is_valid=%s, errors=%d, warnings=%d, doublons_supprimés=%d",
            report.quality_score,
            report.is_valid,
            report.stats.get("nb_errors", 0),
            report.stats.get("nb_warnings", 0),
            report.stats.get("duplicates_removed", 0),
        )

        # Enrichissement LLM (optionnel)
        if GROQ_API_KEY:
            logger.info("Enrichissement LLM du validation_summary...")
            report = _enrich_with_llm(corrected_chain, report)
            logger.info("Summary : %s", report.validation_summary[:120])
        else:
            logger.info("GROQ_API_KEY absente — mode fallback déterministe complet")

        logger.info("═══ ChainValidator : terminé ═══")
        return {
            "security_chain": corrected_chain,
            "validation_report": report,
        }

    except Exception as exc:
        logger.error("chain_validator_node a levé une exception : %s", exc, exc_info=True)
        # Fallback : rapport d'erreur interne
        try:
            corrected_chain, report = validate_chain(chain)
            logger.warning("Fallback : validation déterministe récupérée après exception")
            return {"security_chain": corrected_chain, "validation_report": report}
        except Exception as exc2:
            logger.error("Fallback validation aussi échoué : %s", exc2)
            return {}
