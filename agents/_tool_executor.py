"""
agents/_tool_executor.py — Helpers communs aux 3 agents workers.

Fournit :
- ``invoke_tool_by_name`` : exécute un outil @tool par son nom
- ``run_agentic_loop``    : boucle LLM + tool-calling générique
- ``get_tool_results``    : extrait les résultats d'un outil depuis les messages

Ces fonctions centralisent la logique répétitive pour que chaque worker
reste court et lisible.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def invoke_tool_by_name(
    tools_dict: dict[str, Any],
    tool_name: str,
    tool_args: dict,
) -> Any:
    """Invoque un outil @tool par son nom depuis un mapping nom → outil.

    Args:
        tools_dict: Mapping ``{nom_outil: fonction_@tool}``, construit depuis
            la liste des outils avec ``{t.name: t for t in tools}``.
        tool_name: Nom de l'outil demandé par le LLM.
        tool_args: Arguments transmis par le LLM pour cet appel.

    Returns:
        Résultat de ``tool.invoke(tool_args)``, ou un dict d'erreur si
        l'outil est inconnu ou lève une exception.

    Examples:
        >>> tools_dict = {t.name: t for t in [list_available_topologies]}
        >>> invoke_tool_by_name(tools_dict, "list_available_topologies", {})
        [{"name": "Abilene", ...}]
    """
    tool = tools_dict.get(tool_name)
    if tool is None:
        logger.warning("Outil inconnu demandé par le LLM : '%s'", tool_name)
        return {"status": "error", "message": f"Outil inconnu : '{tool_name}'"}

    try:
        logger.info("  → Outil : %s  args=%s", tool_name, tool_args)
        result = tool.invoke(tool_args)
        logger.info("  ← Résultat : %s", str(result)[:250])
        return result
    except Exception as exc:
        logger.error("  ✗ Outil '%s' a échoué : %s", tool_name, exc)
        return {"status": "error", "message": str(exc)}


def run_agentic_loop(
    llm: Any,
    system_prompt: str,
    context: str,
    tools: list,
    max_iterations: int = 5,
) -> list:
    """Boucle agentique générique : LLM + tool-calling jusqu'à convergence.

    Invoque le LLM en boucle.  À chaque tour, si le LLM produit des
    ``tool_calls``, les outils sont exécutés et leurs résultats ajoutés
    aux messages.  La boucle s'arrête quand le LLM ne demande plus d'outils
    (réponse finale) ou quand ``max_iterations`` est atteint.

    Args:
        llm: LLM LangChain **déjà configuré avec bind_tools()**.
        system_prompt: Prompt système (instructions de rôle du worker).
        context: Message humain initial (contexte de la tâche).
        tools: Liste des fonctions @tool disponibles — utilisées pour
            l'exécution des appels (pas pour le binding, déjà fait).
        max_iterations: Nombre maximal de tours LLM. Défaut 5.

    Returns:
        list: Tous les messages échangés (SystemMessage, HumanMessage,
            AIMessage, ToolMessage).  Utilisez ``get_tool_results`` pour
            extraire les résultats des outils.

    Examples:
        >>> bound_llm = ChatGroq(...).bind_tools(MY_TOOLS)
        >>> messages = run_agentic_loop(bound_llm, PROMPT, context, MY_TOOLS)
    """
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    tools_dict: dict[str, Any] = {t.name: t for t in tools}
    messages: list = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=context),
    ]
    failed_calls: list[str] = []  # détection des échecs répétés du même outil

    for i in range(max_iterations):
        response = llm.invoke(messages)
        messages.append(response)

        if not response.tool_calls:
            logger.info(
                "Agent terminé après %d itération(s) (pas de tool_calls supplémentaires)",
                i + 1,
            )
            break

        logger.info("Tour %d : %d tool call(s)", i + 1, len(response.tool_calls))

        abort = False
        for tc in response.tool_calls:
            result = invoke_tool_by_name(tools_dict, tc["name"], tc["args"])
            messages.append(
                ToolMessage(
                    content=json.dumps(result, default=str, ensure_ascii=False),
                    tool_call_id=tc["id"],
                )
            )

            # Détection des échecs répétés du même outil (3 fois de suite → abandon)
            if isinstance(result, dict) and result.get("status") == "error":
                failed_calls.append(tc["name"])
                if len(failed_calls) >= 3 and failed_calls[-3:] == [tc["name"]] * 3:
                    logger.warning(
                        "Outil '%s' a échoué 3 fois de suite — abandon de la boucle",
                        tc["name"],
                    )
                    abort = True
            else:
                failed_calls = []  # reset si l'outil réussit

        if abort:
            break

    return messages


def get_tool_results(messages: list, tool_name: str) -> list[dict]:
    """Extrait tous les résultats d'un outil spécifique depuis les messages.

    Corrèle les ``tool_call_id`` des AIMessages avec les ToolMessages pour
    identifier les résultats appartenant au bon outil.

    Args:
        messages: Liste complète des messages issus de ``run_agentic_loop``.
        tool_name: Nom exact de l'outil (``tool.name``).

    Returns:
        list[dict]: Résultats parsés (JSON → dict), dans l'ordre d'appel.
            Les ToolMessages non-parsables sont ignorés avec un warning.

    Examples:
        >>> results = get_tool_results(messages, "deploy_topology_in_mininet")
        >>> results[0]["status"]
        'success'
    """
    from langchain_core.messages import ToolMessage

    # Construire mapping tool_call_id → tool_name depuis les AIMessages
    call_id_to_name: dict[str, str] = {}
    for msg in messages:
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                call_id_to_name[tc["id"]] = tc["name"]

    # Collecter les ToolMessages du bon outil
    results: list[dict] = []
    for msg in messages:
        if (
            isinstance(msg, ToolMessage)
            and call_id_to_name.get(msg.tool_call_id) == tool_name
        ):
            try:
                results.append(json.loads(msg.content))
            except (json.JSONDecodeError, TypeError):
                logger.warning(
                    "Impossible de parser le résultat JSON de l'outil '%s'", tool_name
                )

    return results
