"""architectures/supervisor/behavior_supervisor.py

Pipeline COMPORTEMENTAL (liste blanche) orchestré par un SUPERVISEUR — et non
plus en script linéaire. On retrouve exactement le fonctionnement voulu :

  · Les agents ne se parlent JAMAIS directement. Ils lisent et écrivent un ÉTAT
    PARTAGÉ (BehaviorState) fourni par LangGraph.
  · Au démarrage, le Superviseur consulte l'état : l'Analyseur a-t-il travaillé ?
    Sinon il lui donne l'ordre. L'Analyseur finit, met l'état à jour, REDONNE la
    main au Superviseur. Et ainsi de suite : Firewall, IDS, Vérificateur, Déployeur.
  · Le Vérificateur contrôle la chaîne ENTIÈRE. S'il trouve une incohérence, il
    n'appelle pas l'agent fautif lui-même : il l'inscrit dans l'état, et c'est le
    SUPERVISEUR qui, en reconsultant l'état, efface le volet fautif et renvoie
    l'ordre à l'agent concerné (Firewall ou IDS). Un compteur borne les reprises.

Topologie (hub-and-spoke) :

        ┌──────────────────────────────────────────────┐
        ▼                                                │
   Superviseur ──▶ Analyseur ─┐                          │
        │  ▲                  │                          │
        │  └──────────────────┘  (chaque agent redonne   │
        │     ▶ Firewall ────────  la main au Superviseur)│
        │     ▶ IDS ─────────────                         │
        │     ▶ Vérificateur ──── (fault_agent) ──────────┘
        │     ▶ Déployeur
        └──▶ END
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import re
import sys
from typing import Literal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pydantic import BaseModel, Field
from langgraph.graph import END, START, StateGraph

from tools.behavior_traces import enrich
from tools.behavior_chain import brief, reference_chain
from agents.chain_checker import check_chain, ERROR

logger = logging.getLogger(__name__)

MAX_CORRECTION_ATTEMPTS = 3   # boucle INTERNE d'un agent LLM (feedback ciblé)
MAX_VERIF_ATTEMPTS = 2        # reprises pilotées par le Vérificateur via le Superviseur

Route = Literal["analyzer", "firewall", "ids", "verifier", "deployer", "end"]


# ═══════════════════════════════════════════════════════════════════════════
# État PARTAGÉ — la seule chose que les agents ont en commun
# ═══════════════════════════════════════════════════════════════════════════
class BehaviorState(BaseModel):
    # ── entrées ──
    app: str
    model: str = "llama-3.3-70b-versatile"
    use_llm: bool = True

    # ── sorties des agents (None = « pas encore fait » → sert au routage) ──
    profile: dict | None = None                 # Analyseur
    firewall_decision: dict | None = None       # Firewall (LLM)
    firewall_report: dict | None = None
    ids_decision: dict | None = None            # IDS (LLM)
    ids_report: dict | None = None
    chain: dict | None = None                   # assemblée par le Vérificateur
    verification_report: dict | None = None     # Vérificateur (déterministe)
    deployment_result: dict | None = None       # Déployeur

    # ── pilotage de la reprise Vérificateur → agent fautif ──
    fault_agent: str | None = None
    verif_attempts: int = 0
    used_fallback: bool = False

    # ── routage / trace ──
    next_agent: Route = "analyzer"
    agents_invoked: list[str] = Field(default_factory=list)
    supervisor_log: list[str] = Field(default_factory=list)

    # ── pour la démo déterministe : forcer une faute au 1er passage ──
    sabotage: str | None = None                 # "firewall" | "ids" | None


# ═══════════════════════════════════════════════════════════════════════════
# Helpers LLM + contrôles (identiques au pipeline, mais réutilisés ici)
# ═══════════════════════════════════════════════════════════════════════════
def _key() -> str:
    env = pathlib.Path(__file__).resolve().parents[2] / ".env"
    m = re.search(r"gsk_[A-Za-z0-9]+", env.read_text()) if env.exists() else None
    return os.environ.get("GROQ_API_KEY") or (m.group(0) if m else "")


def _parse(txt: str) -> dict | None:
    m = re.search(r"\{.*\}", txt, re.DOTALL)
    try:
        return json.loads(m.group(0)) if m else None
    except Exception:
        return None


def _observed(profile):
    return [s for s in profile["services"] if s.get("destinations")]


FW_PROMPT = """Tu es l'agent PARE-FEU. À partir du comportement réseau observé, décide pour CHAQUE service une action de LISTE BLANCHE.
- "ALLOW" pour un service normal.
- "ALLOW_AND_INSPECT" si le service est impliqué dans un enchaînement RARE (à surveiller).
- N'invente AUCUN service absent du comportement. Politique par défaut OBLIGATOIRE : "DENY".

COMPORTEMENT :
{brief}

Réponds UNIQUEMENT en JSON :
{{"default_action":"DENY","services":[{{"service":"<label exact>","action":"ALLOW|ALLOW_AND_INSPECT"}}]}}"""

IDS_PROMPT = """Tu es l'agent IDS. Voici les services mis sous surveillance par le pare-feu et les boucles observées.
Décide pour lesquels créer une signature de détection (beaconing). Il faut AU MOINS une signature par service sous surveillance.

Services sous surveillance : {watch}
Boucles observées (service : cadence médiane) : {loops}

Réponds UNIQUEMENT en JSON : {{"signatures":[{{"service":"<label>"}}]}}"""


def _fw_check(dec, profile):
    obs = {s["label"] for s in _observed(profile)}
    beh = {s["label"] for s in profile["services"]}
    got = {d.get("service") for d in dec.get("services", [])}
    errs = []
    for m in sorted(obs - got):
        errs.append(("couverture", f"service « {m} » oublié"))
    for m in sorted(got - beh):
        errs.append(("invention", f"service « {m} » inventé (absent du comportement)"))
    if str(dec.get("default_action", "")).upper() != "DENY":
        errs.append(("default-deny", "la politique par défaut doit être DENY"))
    return errs


def _ids_check(ids_dec, watch):
    got = {s.get("service") for s in ids_dec.get("signatures", [])}
    return [("inspect-sans-signature", f"service surveillé « {m} » sans signature IDS")
            for m in sorted(set(watch) - got)]


def _usage(resp):
    u = getattr(resp, "usage_metadata", None) or {}
    if u:
        return u.get("input_tokens", 0), u.get("output_tokens", 0)
    t = (getattr(resp, "response_metadata", {}) or {}).get("token_usage", {})
    return t.get("prompt_tokens", 0), t.get("completion_tokens", 0)


def _run_llm_agent(llm, prompt, checker, max_attempts=MAX_CORRECTION_ATTEMPTS):
    """Boucle de correction INTERNE d'un agent LLM (feedback ciblé)."""
    calls = retries = in_tok = out_tok = 0
    errors, dec, feedback = [], None, ""
    for _ in range(max_attempts):
        calls += 1
        try:
            resp = llm.invoke(prompt + ("\n\nCorrige ces erreurs :\n" + feedback if feedback else ""))
        except Exception as exc:
            errors.append(f"llm_error:{type(exc).__name__}"); break
        it, ot = _usage(resp); in_tok += it; out_tok += ot
        d = _parse(resp.content)
        if not d:
            errors.append("json-illisible"); retries += 1
            feedback = "Ta réponse n'était pas un JSON valide."; continue
        errs = checker(d)
        if not errs:
            dec = d; break
        retries += 1; dec = d
        errors += [c for c, _ in errs]
        feedback = "\n".join("- " + m for _, m in errs)
    return dec, {"calls": calls, "retries": retries, "errors": errors,
                 "in_tok": in_tok, "out_tok": out_tok,
                 "source": "llm" if dec is not None else "echec"}


def _assemble(fw_dec, ids_dec, profile):
    by = {s["label"]: s for s in profile["services"]}
    fw = []
    for d in (fw_dec or {}).get("services", []):
        lbl = str(d.get("service", "")).strip()
        act = str(d.get("action", "ALLOW")).upper()
        act = act if act in ("ALLOW", "ALLOW_AND_INSPECT") else "ALLOW"
        svc = by.get(lbl)
        protos = (svc.get("protocols") if svc else None) or ["TCP"]
        for p in protos:
            fw.append({"service": lbl, "spec": svc["spec"] if svc else {"kind": "unknown"},
                       "protocol": p, "action": act,
                       "destinations": [x["ip"] for x in svc.get("destinations", [])] if svc else []})
    ids = []
    for s in (ids_dec or {}).get("signatures", []):
        lbl = str(s.get("service", "")).strip()
        svc = by.get(lbl)
        thr = (svc.get("periodicity", {}) or {}).get("median_interval_s") if svc else None
        ids.append({"service": lbl, "reason": "surveillance", "beaconing_threshold_s": thr})
    return {"app": profile["app_name"], "default_action": (fw_dec or {}).get("default_action", "?"),
            "firewall_rules": fw, "ids_signatures": ids}


def _watch_list(fw_dec):
    return [d["service"] for d in (fw_dec or {}).get("services", [])
            if str(d.get("action", "")).upper() == "ALLOW_AND_INSPECT"]


# ═══════════════════════════════════════════════════════════════════════════
# LES AGENTS — chacun lit l'état, fait SON travail, écrit l'état, revient
# ═══════════════════════════════════════════════════════════════════════════
def analyzer_node(state: BehaviorState) -> dict:
    """Déterministe : lit l'automate + les traces → profil comportemental."""
    prof = enrich(state.app)
    logger.info("Analyseur : profil de « %s » (%d services, %d rares)",
                state.app, prof["stats"]["n_services"], prof["stats"]["n_rare"])
    return {"profile": prof}


def _reference_fw_decision(prof, sabotage=None):
    """Décision Firewall CORRECTE dérivée de la référence (mode sans LLM).
    Si sabotage == 'firewall', on omet volontairement le 1er service (faute
    « couverture ») pour démontrer la reprise pilotée par le Vérificateur."""
    ref = reference_chain(prof)
    svcs = [{"service": r["service"], "action": r["action"]} for r in ref["firewall_rules"]]
    # dédoublonnage (un service peut avoir plusieurs protocoles)
    seen, uniq = set(), []
    for s in svcs:
        if s["service"] not in seen:
            seen.add(s["service"]); uniq.append(s)
    if sabotage == "firewall" and len(uniq) > 1:
        uniq = uniq[1:]  # on « oublie » un service → faute de couverture
    return {"default_action": "DENY", "services": uniq}


def firewall_node(state: BehaviorState) -> dict:
    """LLM (ou déterministe) : décide ALLOW / ALLOW_AND_INSPECT par service."""
    prof = state.profile
    if state.use_llm:
        llm = _make_llm(state.model)
        dec, rep = _run_llm_agent(llm, FW_PROMPT.format(brief=brief(prof)),
                                  lambda d: _fw_check(d, prof))
        if dec is None:  # repli déterministe
            dec = _reference_fw_decision(prof)
            rep["source"] = "fallback"
    else:
        # mode démo : sabotage possible au 1er passage seulement
        sab = state.sabotage if state.verif_attempts == 0 else None
        dec = _reference_fw_decision(prof, sabotage=sab)
        rep = {"calls": 1, "retries": 0, "errors": [], "in_tok": 0, "out_tok": 0,
               "source": "deterministe"}
    logger.info("Firewall : %d services décidés (source=%s)", len(dec["services"]), rep["source"])
    return {"firewall_decision": dec, "firewall_report": rep}


def ids_node(state: BehaviorState) -> dict:
    """LLM (ou déterministe) : décide quelles boucles/services surveiller."""
    prof = state.profile
    watch = _watch_list(state.firewall_decision)
    if state.use_llm:
        loops = ", ".join(
            f"{l['service']}:{(next((x for x in prof['services'] if x['label']==l['service']),{}).get('periodicity',{}) or {}).get('median_interval_s')}"
            for l in prof["loops"])
        llm = _make_llm(state.model)
        dec, rep = _run_llm_agent(
            llm, IDS_PROMPT.format(watch=watch or "(aucun)", loops=loops or "(aucune)"),
            lambda d: _ids_check(d, watch))
        if dec is None:
            dec = {"signatures": [{"service": s} for s in watch]}
            rep["source"] = "fallback"
    else:
        sab = state.sabotage if state.verif_attempts == 0 else None
        sigs = list(watch)
        if sab == "ids" and sigs:
            sigs = sigs[1:]  # on oublie une signature → inspect-sans-signature
        dec = {"signatures": [{"service": s} for s in sigs]}
        rep = {"calls": 1, "retries": 0, "errors": [], "in_tok": 0, "out_tok": 0,
               "source": "deterministe"}
    logger.info("IDS : %d signatures (source=%s)", len(dec["signatures"]), rep["source"])
    return {"ids_decision": dec, "ids_report": rep}


# quelles catégories d'erreur incriminent quel agent (pour la reprise ciblée)
_FAULT_OF = {
    "coverage": "firewall",              # service observé absent de la chaîne
    "invented_service": "firewall",      # service inventé
    "missing_default_deny": "firewall",  # politique par défaut ≠ DENY
    "conflict": "firewall",              # ALLOW et ALLOW_AND_INSPECT sur le même service
    "inspect_without_signature": "ids",  # service surveillé sans signature
}


def verifier_node(state: BehaviorState) -> dict:
    """Déterministe : assemble la chaîne ENTIÈRE et la contrôle. En cas
    d'ERREUR, désigne l'agent fautif dans l'état — mais NE le rappelle pas
    lui-même : c'est le Superviseur qui décidera de la reprise."""
    chain = _assemble(state.firewall_decision, state.ids_decision, state.profile)
    rep = check_chain(chain, state.profile)
    fault = None
    if not rep["is_valid"]:
        for issue in rep["issues"]:
            if issue["severity"] == ERROR:
                fault = _FAULT_OF.get(issue["category"])
                if fault:
                    break
    logger.info("Vérificateur : chaîne %s (score %d) — agent fautif=%s",
                "VALIDE" if rep["is_valid"] else "INVALIDE", rep["quality_score"], fault)
    return {"chain": chain, "verification_report": rep, "fault_agent": fault}


def deployer_node(state: BehaviorState) -> dict:
    """Déterministe : si la chaîne est invalide (reprises épuisées), on retombe
    sur la chaîne de référence ; puis on « déploie » (ici : statut + comptes)."""
    used_fallback = not state.verification_report["is_valid"]
    chain = reference_chain(state.profile) if used_fallback else state.chain
    result = {"status": "deployed",
              "n_firewall_rules": len(chain["firewall_rules"]),
              "n_ids_signatures": len(chain["ids_signatures"]),
              "used_fallback": used_fallback}
    logger.info("Déployeur : %d règles FW, %d signatures IDS (fallback=%s)",
                result["n_firewall_rules"], result["n_ids_signatures"], used_fallback)
    return {"deployment_result": result, "chain": chain, "used_fallback": used_fallback}


# ═══════════════════════════════════════════════════════════════════════════
# LE SUPERVISEUR — consulte l'état, donne l'ordre, ne fait AUCUN travail métier
# ═══════════════════════════════════════════════════════════════════════════
def _decide_next(state: BehaviorState) -> tuple[Route, str, dict]:
    """Renvoie (route, raison, updates). `updates` = effacements d'état quand le
    Superviseur décide une REPRISE (remettre un volet à None pour re-router)."""
    if state.profile is None:
        return "analyzer", "Automate pas encore analysé → Analyseur.", {}

    if state.firewall_decision is None:
        return "firewall", "Profil prêt, pare-feu non produit → Firewall.", {}

    if state.ids_decision is None:
        return "ids", "Pare-feu prêt, IDS non produit → IDS.", {}

    if state.verification_report is None:
        return "verifier", "Volets prêts, chaîne non vérifiée → Vérificateur.", {}

    # Le Vérificateur a parlé. Chaîne incohérente + reprises restantes + agent
    # fautif identifié → le Superviseur EFFACE le volet fautif et renvoie l'ordre.
    rep = state.verification_report
    if (not rep["is_valid"] and state.fault_agent
            and state.verif_attempts < MAX_VERIF_ATTEMPTS):
        clear = {"firewall": "firewall_decision", "ids": "ids_decision"}[state.fault_agent]
        updates = {clear: None, "verification_report": None, "fault_agent": None,
                   "verif_attempts": state.verif_attempts + 1}
        return (state.fault_agent,
                f"Chaîne INVALIDE (reprise {state.verif_attempts + 1}/{MAX_VERIF_ATTEMPTS}) "
                f"→ le Superviseur efface le volet « {clear} » et renvoie l'ordre à "
                f"l'agent {state.fault_agent.upper()}.", updates)

    if state.deployment_result is None:
        why = "Chaîne validée" if rep["is_valid"] else "Reprises épuisées (repli)"
        return "deployer", f"{why} → Déployeur.", {}

    return "end", "Chaîne déployée → fin de l'orchestration.", {}


def supervisor_node(state: BehaviorState) -> dict:
    turn = len(state.supervisor_log) + 1
    route, reason, updates = _decide_next(state)
    logger.info("═══ Superviseur (tour %d) → %s ═══  %s", turn, route, reason)
    out = dict(updates)
    out["next_agent"] = route
    out["supervisor_log"] = state.supervisor_log + [f"[tour {turn}] {route} — {reason}"]
    if route != "end":
        out["agents_invoked"] = state.agents_invoked + [route]
    return out


def route_from_supervisor(state: BehaviorState) -> str:
    return state.next_agent


# ═══════════════════════════════════════════════════════════════════════════
# Construction du graphe
# ═══════════════════════════════════════════════════════════════════════════
def _make_llm(model):
    from langchain_groq import ChatGroq
    return ChatGroq(model=model, api_key=_key(), temperature=0,
                    request_timeout=45, max_retries=1)


def _wrap(node_fn):
    def wrapped(state: BehaviorState) -> dict:
        try:
            return node_fn(state) or {}
        except Exception as exc:
            logger.error("Erreur dans '%s' : %s", node_fn.__name__, exc, exc_info=True)
            return {}
    wrapped.__name__ = node_fn.__name__
    return wrapped


def build_behavior_graph():
    b = StateGraph(BehaviorState)
    b.add_node("supervisor", supervisor_node)
    b.add_node("analyzer", _wrap(analyzer_node))
    b.add_node("firewall", _wrap(firewall_node))
    b.add_node("ids", _wrap(ids_node))
    b.add_node("verifier", _wrap(verifier_node))
    b.add_node("deployer", _wrap(deployer_node))

    b.add_edge(START, "supervisor")
    b.add_conditional_edges("supervisor", route_from_supervisor, {
        "analyzer": "analyzer", "firewall": "firewall", "ids": "ids",
        "verifier": "verifier", "deployer": "deployer", "end": END,
    })
    # chaque agent REDONNE la main au Superviseur (aucun lien direct entre agents)
    for n in ("analyzer", "firewall", "ids", "verifier", "deployer"):
        b.add_edge(n, "supervisor")

    compiled = b.compile()
    logger.info("Graphe Superviseur COMPORTEMENTAL compilé.")
    return compiled


# ═══════════════════════════════════════════════════════════════════════════
# Démo : orchestration réelle SANS quota (use_llm=False), avec une faute forcée
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    sabotage = sys.argv[2] if len(sys.argv) > 2 else "firewall"

    graph = build_behavior_graph()
    print(f"\n╔══ Orchestration Superviseur — app={app}, faute forcée={sabotage} ══╗\n")
    final = graph.invoke(BehaviorState(app=app, use_llm=False, sabotage=sabotage))
    final = BehaviorState(**final) if isinstance(final, dict) else final

    print("\n─── JOURNAL DU SUPERVISEUR (qui a donné quel ordre) ───")
    for line in final.supervisor_log:
        print("  " + line)
    print("\n─── ORDRE RÉEL D'INVOCATION DES AGENTS ───")
    print("  " + " → ".join(final.agents_invoked))
    print("\n─── RÉSULTAT ───")
    print(f"  chaîne valide : {final.verification_report['is_valid']}  "
          f"(score {final.verification_report['quality_score']}/100)")
    print(f"  déploiement   : {final.deployment_result}")
    print(f"  repli utilisé : {final.used_fallback}")
