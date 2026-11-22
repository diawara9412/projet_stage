"""
architectures/supervisor/llm_runtime.py — Réglage RUNTIME partagé de la
température des agents LLM (firewall, ids, ips).

But : permettre à une expérience (benchmark/temperature_experiment.py) de faire
varier la température SANS modifier la logique des agents ni la config par défaut.

Mécanisme PUREMENT ADDITIF :
  - tant qu'aucune surcharge n'est posée, ``get_temperature(default)`` renvoie le
    ``default`` (la valeur normale du projet, WORKER_TEMPERATURE) → comportement
    INCHANGÉ ;
  - une expérience appelle ``set_temperature(t)`` pour forcer une valeur, puis
    ``reset_temperature()`` pour revenir au comportement normal.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# None = pas de surcharge → on utilise le défaut passé par l'agent.
_OVERRIDE: float | None = None


def set_temperature(value: float) -> None:
    """Force une température pour tous les agents LLM (utilisé par l'expérience)."""
    global _OVERRIDE
    _OVERRIDE = float(value)
    logger.info("Température LLM forcée à %.2f (surcharge runtime)", _OVERRIDE)


def reset_temperature() -> None:
    """Annule la surcharge → retour au défaut du projet."""
    global _OVERRIDE
    _OVERRIDE = None


def get_temperature(default: float) -> float:
    """Renvoie la température à utiliser : la surcharge si posée, sinon le défaut."""
    return _OVERRIDE if _OVERRIDE is not None else default
