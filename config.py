"""
config.py — Configuration centralisée du système SDN multi-agents.

Charge les variables depuis le fichier .env via python-dotenv et expose
des constantes typées utilisées par les agents et les outils.

Usage::

    from config import GROQ_API_KEY, SUPERVISOR_MODEL

Note : GROQ_API_KEY est obligatoire pour les appels LLM réels.
       Sans clé, le Supervisor bascule automatiquement sur son mode
       déterministe (fallback), ce qui permet de tester la logique du
       graphe sans clé API.
"""

import logging
import os
import warnings

from dotenv import load_dotenv

# Charge .env depuis le répertoire courant (racine du projet)
load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM — modèles et paramètres
# ---------------------------------------------------------------------------

GROQ_API_KEY: str | None = os.getenv("GROQ_API_KEY") or None

SUPERVISOR_MODEL: str = os.getenv("SUPERVISOR_MODEL", "llama-3.3-70b-versatile")
WORKER_MODEL: str = os.getenv("WORKER_MODEL", "llama-3.3-70b-versatile")

SUPERVISOR_TEMPERATURE: float = float(os.getenv("SUPERVISOR_TEMPERATURE", "0.2"))
WORKER_TEMPERATURE: float = float(os.getenv("WORKER_TEMPERATURE", "0.4"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "5"))

# ---------------------------------------------------------------------------
# Validation — avertissement si clé manquante (non bloquant à l'import)
# Les appels LLM échoueront proprement plus tard avec un message clair.
# ---------------------------------------------------------------------------

if not GROQ_API_KEY:
    warnings.warn(
        "\n⚠️  GROQ_API_KEY manquante dans le fichier .env.\n"
        "   Les appels LLM utiliseront le mode fallback déterministe.\n"
        "   Obtenez une clé gratuite sur https://console.groq.com\n"
        "   puis ajoutez GROQ_API_KEY=gsk_xxx dans votre fichier .env",
        RuntimeWarning,
        stacklevel=2,
    )
    logger.warning("GROQ_API_KEY absente — mode fallback actif.")
