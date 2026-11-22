"""
agents/chain_generator.py — Agent ChainGenerator du système Phase 2.

Transforme une AutomateAnalysis (produite par ChainAnalyzer et stockée dans
le GraphState) en une SecurityChain concrète contenant des règles firewall,
des signatures IDS et des actions IPS prêtes pour le PolicyEnforcer.

Flux de traitement
------------------
1. Garde : pas d'AutomateAnalysis → retourne {} immédiatement.
2. Garde : SecurityChain déjà présente → idempotent, retourne {}.
3. Génération déterministe via ``generate_chain_from_analysis``.
4. Enrichissement LLM optionnel : résumé narratif + validation de la chaîne.
5. Retourne ``{"security_chain": SecurityChain}``.
"""

import json
import logging
import re
import warnings

from state import AutomateAnalysis, GraphState, SecurityChain
from tools.chain_tools import generate_chain_from_analysis

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL, WORKER_TEMPERATURE

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

CHAIN_GENERATOR_SYSTEM_PROMPT = """Tu es l'agent ChainGenerator d'un système de sécurité réseau SDN basé sur LangGraph.

## Ta mission

Valider et enrichir une chaîne de sécurité générée automatiquement à partir de l'analyse d'un automate réseau. La chaîne contient des règles firewall, des signatures IDS et des actions IPS.

## Ce que tu reçois

Un résumé de la chaîne déterministe générée : règles BLOCK/ALLOW, signatures IDS actives, actions IPS, et le contexte de l'application analysée.

## Ce que tu dois produire

Un objet JSON STRICT avec exactement ces deux champs :

```json
{
  "generation_summary": "Résumé narratif de 3 à 5 phrases expliquant la chaîne générée : quelles menaces sont bloquées, quels services sont autorisés, niveau de protection et éventuelles recommandations supplémentaires.",
  "extra_rules": []
}
```

Le champ ``extra_rules`` est une liste vide ``[]`` par défaut. Tu peux y ajouter des règles supplémentaires si tu détectes des lacunes critiques (format: {"type": "FIREWALL_BLOCK|IDS|IPS", "description": "...", "rationale": "..."}).

## Règles

- Le ``generation_summary`` doit référencer les IPs bloquées, les services autorisés et les types d'attaques détectés.
- Cite des tactiques MITRE ATT&CK quand c'est pertinent (ex: T1071 pour C2 over HTTP).
- Ne modifie pas les règles déterministes existantes, seulement ajouter si nécessaire.
- Réponds UNIQUEMENT avec le JSON, sans markdown ni texte autour.
"""

# ---------------------------------------------------------------------------
# Enrichissement LLM
# ---------------------------------------------------------------------------

def _enrich_with_llm(analysis: AutomateAnalysis, chain: SecurityChain) -> SecurityChain:
    """Enrichit le generation_summary via Llama et valide la chaîne générée."""
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_groq import ChatGroq

        llm = ChatGroq(
            api_key=GROQ_API_KEY,
            model=WORKER_MODEL,
            temperature=0.1,
        )

        # Résumé de la chaîne pour le LLM
        block_rules = [r for r in chain.firewall_rules if r.action == "BLOCK"]
        allow_rules = [r for r in chain.firewall_rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT")]

        block_summary = "\n".join(
            f"  - {r.id}: BLOCK {r.dst_ip}:{r.dst_port}/{r.protocol} (priorité {r.priority})"
            for r in block_rules
        ) or "  (aucune)"

        allow_summary = "\n".join(
            f"  - {r.id}: ALLOW {r.dst_ip}:{r.dst_port} — {r.comment}"
            for r in allow_rules
        ) or "  (aucune)"

        ids_summary = "\n".join(
            f"  - {s.id}: [{s.severity}] {s.name} ({s.pattern_type})"
            for s in chain.ids_signatures
        ) or "  (aucune)"

        ips_summary = "\n".join(
            f"  - {a.id}: {a.action} sur {a.on_signature}"
            for a in chain.ips_actions
        ) or "  (aucune)"

        context = f"""Application : {chain.source_app_name} — Risque global : {chain.global_risk_level}
Score de suspicion : {analysis.global_suspicion_score}/10
Transitions suspectes traitées : {analysis.nb_suspicious}

Règles BLOCK générées ({len(block_rules)}) :
{block_summary}

Règles ALLOW générées ({len(allow_rules)}) :
{allow_summary}

Signatures IDS ({len(chain.ids_signatures)}) :
{ids_summary}

Actions IPS ({len(chain.ips_actions)}) :
{ips_summary}

Produis le JSON demandé (generation_summary + extra_rules vide si tout est couvert)."""

        response = llm.invoke([
            SystemMessage(content=CHAIN_GENERATOR_SYSTEM_PROMPT),
            HumanMessage(content=context),
        ])

        raw = response.content.strip()
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if not m:
            logger.warning("LLM n'a pas retourné de JSON valide — conservation du résumé déterministe")
            return chain

        data = json.loads(m.group())
        llm_summary = data.get("generation_summary")
        if llm_summary:
            return chain.model_copy(update={"generation_summary": llm_summary})

    except Exception as exc:
        logger.warning("Enrichissement LLM échoué : %s — résumé déterministe conservé", exc)

    return chain


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def chain_generator_node(state: GraphState) -> dict:
    """Nœud ChainGenerator du graphe LangGraph Phase 2.

    Transforme l'AutomateAnalysis du GraphState en SecurityChain.
    Idempotent : ne refait pas le travail si la chaîne existe déjà.

    Args:
        state: État courant du graphe.

    Returns:
        dict: ``{"security_chain": SecurityChain}`` si réussi, ``{}`` sinon.
    """
    logger.info("═══ ChainGenerator : démarrage ═══")

    # Garde 1 : pas d'analyse disponible
    if state.automate_analysis is None:
        logger.error("ChainGenerator : state.automate_analysis est vide — impossible de générer")
        return {}

    # Garde 2 : idempotence
    if state.security_chain is not None:
        logger.info(
            "Chaîne '%s' déjà générée — passage de la main",
            state.security_chain.chain_id,
        )
        return {}

    analysis = state.automate_analysis

    try:
        # Génération déterministe
        chain = generate_chain_from_analysis(analysis)
        nb_block = sum(1 for r in chain.firewall_rules if r.action == "BLOCK")
        nb_allow = sum(1 for r in chain.firewall_rules if r.action in ("ALLOW", "ALLOW_AND_INSPECT"))
        logger.info(
            "Chaîne déterministe : %d BLOCK, %d ALLOW, %d IDS, %d IPS — risque=%s",
            nb_block, nb_allow,
            len(chain.ids_signatures), len(chain.ips_actions),
            chain.global_risk_level,
        )

        # Enrichissement LLM (optionnel)
        if GROQ_API_KEY:
            logger.info("Enrichissement LLM du generation_summary...")
            chain = _enrich_with_llm(analysis, chain)
            logger.info("Summary : %s", chain.generation_summary[:120])
        else:
            logger.info("GROQ_API_KEY absente — mode fallback déterministe complet")

        logger.info("═══ ChainGenerator : terminé ═══")
        return {"security_chain": chain}

    except Exception as exc:
        logger.error("chain_generator_node a levé une exception : %s", exc, exc_info=True)
        # Fallback déterministe pur en cas d'erreur partielle
        try:
            chain = generate_chain_from_analysis(analysis)
            logger.warning("Fallback : chaîne déterministe récupérée après exception")
            return {"security_chain": chain}
        except Exception as exc2:
            logger.error("Fallback déterministe aussi échoué : %s", exc2)
            return {}
