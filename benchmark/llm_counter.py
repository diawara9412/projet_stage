"""
benchmark/llm_counter.py — Compteur d'appels LLM (instrumentation NON intrusive).

Principe
--------
Les deux architectures (baseline linéaire et superviseur) appellent toutes le
LLM via la MÊME classe : ``langchain_groq.ChatGroq`` (chaque agent fait
``ChatGroq(...).invoke([...])``). Le « point central » commun est donc la
méthode ``ChatGroq.invoke``.

On l'enveloppe une seule fois (monkeypatch) par une fonction qui :
  1. incrémente un compteur global thread-safe,
  2. note le module appelant (pour ventiler par agent),
  3. appelle la méthode ``invoke`` ORIGINALE et renvoie son résultat tel quel.

C'est PUREMENT ADDITIF : aucune logique métier n'est modifiée, les chaînes
produites sont identiques. Et comme on instrumente du code PARTAGÉ par les deux
architectures, on compte EXACTEMENT de la même façon des deux côtés.

Usage
-----
    from benchmark.llm_counter import install, reset, snapshot
    install()                 # à appeler UNE fois, avant les runs
    reset()                   # remet le compteur à zéro avant un run
    graph.invoke(...)         # exécution mesurée
    total, by_caller = snapshot()
"""

from __future__ import annotations

import inspect
import logging
import threading
from collections import Counter

logger = logging.getLogger(__name__)

# ── État global protégé par un verrou (thread-safe) ─────────────────────────
_lock = threading.Lock()
_total_calls: int = 0
_calls_by_caller: Counter = Counter()

# Garde anti-double-patch + référence vers la méthode originale
_installed: bool = False
_original_invoke = None

# Tokens (additif) : sommés depuis usage_metadata des réponses, si disponibles.
_tokens_in: int = 0
_tokens_out: int = 0
_tokens_seen: bool = False  # True dès qu'au moins une réponse a fourni des tokens

# Détection d'erreur d'authentification/quota (401) — pour arrêter proprement.
_auth_error: bool = False

# Préfixes de modules considérés comme « agents » du projet (pour la ventilation)
_AGENT_PREFIXES = ("agents.", "architectures.supervisor.")


def _looks_like_auth_error(exc: Exception) -> bool:
    """Vrai si l'exception ressemble à un 401 / clé invalide / quota épuisé."""
    s = str(exc).lower()
    return any(k in s for k in ("401", "invalid_api_key", "invalid api key",
                                "authentication", "unauthorized", "quota"))


def _capture_tokens(result) -> None:
    """Somme les tokens de la réponse si disponibles (usage_metadata / token_usage)."""
    global _tokens_in, _tokens_out, _tokens_seen
    try:
        um = getattr(result, "usage_metadata", None)
        if um:
            i, o = um.get("input_tokens"), um.get("output_tokens")
        else:
            tu = (getattr(result, "response_metadata", {}) or {}).get("token_usage", {})
            i, o = tu.get("prompt_tokens"), tu.get("completion_tokens")
        if i is not None or o is not None:
            with _lock:
                _tokens_in += int(i or 0)
                _tokens_out += int(o or 0)
                _tokens_seen = True
    except Exception:
        # Capture des tokens « best effort » : ne jamais perturber l'appel réel.
        pass


def _detect_caller() -> str:
    """Remonte la pile d'appels pour trouver le module agent à l'origine.

    Renvoie le premier nom de module de la pile commençant par un préfixe agent
    (ex. ``agents.chain_analyzer`` ou ``architectures.supervisor.firewall_agent``).
    Renvoie ``"?"`` si aucun n'est trouvé.
    """
    for frame_info in inspect.stack():
        mod = frame_info.frame.f_globals.get("__name__", "")
        if mod.startswith(_AGENT_PREFIXES):
            return mod
    return "?"


def install() -> None:
    """Installe le compteur en enveloppant ``ChatGroq.invoke`` (idempotent)."""
    global _installed, _original_invoke
    if _installed:
        return

    from langchain_groq import ChatGroq

    _original_invoke = ChatGroq.invoke

    def _counting_invoke(self, *args, **kwargs):
        """Wrapper additif : compte, délègue à l'invoke original, capte les tokens."""
        caller = _detect_caller()
        with _lock:
            global _total_calls
            _total_calls += 1
            _calls_by_caller[caller] += 1
        logger.debug("Appel LLM #%d depuis %s", _total_calls, caller)
        # Appel RÉEL inchangé — on n'altère pas le comportement (on re-lève les erreurs).
        try:
            result = _original_invoke(self, *args, **kwargs)
        except Exception as exc:
            if _looks_like_auth_error(exc):
                with _lock:
                    global _auth_error
                    _auth_error = True
            raise  # propage : l'agent gère son fallback comme d'habitude
        _capture_tokens(result)
        return result

    ChatGroq.invoke = _counting_invoke
    _installed = True
    logger.info("llm_counter installé sur ChatGroq.invoke")


def reset() -> None:
    """Remet le compteur (appels + ventilation + tokens + flag 401) à zéro."""
    global _total_calls, _tokens_in, _tokens_out, _tokens_seen, _auth_error
    with _lock:
        _total_calls = 0
        _calls_by_caller.clear()
        _tokens_in = 0
        _tokens_out = 0
        _tokens_seen = False
        _auth_error = False


def snapshot() -> tuple[int, dict[str, int]]:
    """Retourne (total d'appels, dict {module_appelant: nb}) à l'instant T.

    NOTE : signature INCHANGÉE (2-uplet) pour ne pas casser count_llm_calls.py.
    """
    with _lock:
        return _total_calls, dict(_calls_by_caller)


def token_snapshot() -> dict:
    """Retourne les tokens cumulés (additif). ``available=False`` si non fournis."""
    with _lock:
        if not _tokens_seen:
            return {"available": False, "input": 0, "output": 0, "total": 0}
        return {
            "available": True,
            "input": _tokens_in,
            "output": _tokens_out,
            "total": _tokens_in + _tokens_out,
        }


def had_auth_error() -> bool:
    """Vrai si un 401 / clé invalide / quota a été détecté depuis le dernier reset()."""
    with _lock:
        return _auth_error
