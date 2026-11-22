"""
architectures/supervisor/correction_loop.py — Boucle de correction GÉNÉRIQUE pour
les agents LLM de l'architecture superviseur (firewall / ids / ips).

Principe (validé) : « réparer ce qui est sûr, redemander ce qui demande un jugement ».
  1. l'agent GÉNÈRE (LLM) ;
  2. on VÉRIFIE (outils déterministes) ;
  3. on RÉPARE en déterministe (drops sûrs + LAN + priorité — JAMAIS la dédup) ;
  4. s'il reste des fautes de JUGEMENT (couverture, conflit, champ irrécupérable),
     on RE-GÉNÈRE en renvoyant un feedback CIBLÉ, jusqu'à 0 faute ou MAX tentatives ;
  5. à l'épuisement : on garde le MEILLEUR essai + on lève un drapeau (pas de boucle
     infinie).

Garde-fous de conception :
  - Si le 1er passage ne présente AUCUNE faute de jugement (cas pokemon/banking),
    la boucle s'arrête à la tentative 1 → résultat IDENTIQUE à l'ancien comportement.
  - La REDONDANCE n'est jamais traitée ici (ni réparée, ni régénérée) : carve-out
    projet, le score reste pénalisé par validate_chain en fin de pipeline.

La boucle est agnostique au type d'élément (FirewallRule / IdsSignature / IpsAction) :
chaque agent fournit ses callbacks.
"""

from __future__ import annotations

import logging
from typing import Callable

logger = logging.getLogger(__name__)

# 1 génération initiale + 2 re-générations ciblées. Au-delà, le LLM plafonne et
# chaque tentative coûte un appel Groq → on borne pour maîtriser le quota.
DEFAULT_MAX_ATTEMPTS = 3


def run_with_correction(
    *,
    generate: Callable,            # (feedback: str | None) -> (items | None, build_problems)
    verify: Callable,              # (items) -> dict[str, list[problème]]
    deterministic_repair: Callable,  # (items, checks) -> (items, fixes_log)
    residual_judgment: Callable,   # (checks) -> list[problème]  (REDONDANCE exclue)
    build_feedback: Callable,      # (items, residuals) -> str
    agent_score: Callable,         # (checks) -> float (plus haut = meilleur)
    label: str = "agent",
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> dict | None:
    """Exécute la boucle génération → vérif → réparation → (re-génération).

    Returns:
        dict {items, checks, attempts, exhausted, deterministic_fixes,
              residual_problems, agent_score} si au moins un essai a produit des
        éléments exploitables ; ``None`` si le LLM n'a jamais rien produit de
        parsable (→ l'appelant bascule sur son fallback déterministe).
    """
    best: dict | None = None
    feedback: str | None = None
    all_fixes: list[str] = []
    # Profil d'erreurs de la 1ʳᵉ génération exploitable (fiabilité BRUTE du LLM,
    # avant TOUTE correction). Capturé une seule fois ; n'affecte pas le score.
    errors_before: dict[str, int] | None = None
    errors_before_detail: dict[str, list[str]] | None = None  # messages exacts par catégorie

    for attempt in range(1, max_attempts + 1):
        items, _build = generate(feedback)
        if items is None:
            logger.warning("%s : génération LLM infructueuse (tentative %d/%d)",
                           label, attempt, max_attempts)
            # Rien d'exploitable cette tentative : si on n'a aucun « best », on
            # arrête pour laisser l'appelant gérer son fallback déterministe.
            if best is None:
                break
            continue

        # ── Vérification BRUTE (avant toute correction) ─────────────────────
        checks = verify(items)
        # Comptage homogène de TOUS les types d'erreurs de la sortie LLM brute,
        # à la 1ʳᵉ génération produisant des éléments (aucun type exclu).
        if errors_before is None:
            errors_before = {cat: len(probs) for cat, probs in checks.items()}
            errors_before_detail = {
                cat: [p["message"] for p in probs]
                for cat, probs in checks.items() if probs
            }

        # ── Réparation déterministe ─────────────────────────────────────────
        items, fixes = deterministic_repair(items, checks)
        if fixes:
            all_fixes.extend(f"[t{attempt}] {f}" for f in fixes)
        # Re-vérifier APRÈS réparation (les drops/dédup/ajouts ont changé l'état)
        checks = verify(items)

        residuals = residual_judgment(checks)
        score = agent_score(checks)

        # Garder le meilleur essai vu jusqu'ici
        if best is None or score > best["agent_score"]:
            best = {
                "items": items, "checks": checks,
                "attempts": attempt, "agent_score": score,
                "residual_problems": [p["message"] for p in residuals],
            }

        # ── Succès : plus aucune faute de jugement ──────────────────────────
        if not residuals:
            logger.info("%s : 0 faute de jugement à la tentative %d", label, attempt)
            return {
                "items": items, "checks": checks,
                "attempts": attempt, "exhausted": False,
                "deterministic_fixes": all_fixes,
                "residual_problems": [],
                "agent_score": score,
                "errors_before_correction": errors_before or {},
                "errors_before_correction_detail": errors_before_detail or {},
            }

        # ── Sinon : préparer la re-génération ciblée ────────────────────────
        logger.warning("%s : %d faute(s) de jugement après tentative %d → re-génération",
                        label, len(residuals), attempt)
        feedback = build_feedback(items, residuals)

    # ── Épuisement : on garde le meilleur + drapeau ─────────────────────────
    if best is None:
        return None  # le LLM n'a jamais rien produit → fallback côté appelant
    logger.warning("%s : tentatives épuisées (%d) — meilleur essai conservé, "
                   "%d faute(s) résiduelle(s)", label, max_attempts,
                   len(best["residual_problems"]))
    return {
        "items": best["items"], "checks": best["checks"],
        "attempts": max_attempts, "exhausted": True,
        "deterministic_fixes": all_fixes,
        "residual_problems": best["residual_problems"],
        "agent_score": best["agent_score"],
        "errors_before_correction": errors_before or {},
        "errors_before_correction_detail": errors_before_detail or {},
    }
