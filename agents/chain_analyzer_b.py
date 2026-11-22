"""
agents/chain_analyzer_b.py — Analyzer « Condition B » : l'agent fait LUI-MÊME le
travail de sécurité en appelant le pipeline ``enrichment/`` via VRAI tool-calling
(``bind_tools`` ; c'est le LLM qui décide des appels), au lieu de lire un
``*_enriched.json`` déjà annoté (Condition A).

Deux variantes d'assemblage final (paramètre ``assembly_mode``)
--------------------------------------------------------------
- ``"deterministic"`` (B-det, variante PRINCIPALE) : le LLM appelle
  ``classify_destination`` (déterministe) pour chaque IP ; l'``AutomateAnalysis``
  finale est assemblée DÉTERMINISTEMENT depuis les sorties d'outils, en réutilisant
  ``_analyze_deterministic`` de la Condition A. → à couverture pleine, B-det == A.
  Par construction, AUCUNE divergence de raisonnement possible (seul écart possible =
  la COUVERTURE : des IP que le LLM n'a pas classées).

- ``"llm"`` (B-llm, ABLATION) : ``classify_destination`` n'est PAS exposé. Le LLM
  ne reçoit que les signaux BRUTS (load_traces + resolve_asn + reputation) et les
  définitions de catégories/seuils du classifieur, et DÉCIDE LUI-MÊME flags/score.
  → deux causes d'écart vs A : COUVERTURE (IP manquée) ET RAISONNEMENT (IP classée
  mais flags/score ≠ A).

MITRE reste de l'enrichissement NARRATIF, pas un outil déterministe.
"""

from __future__ import annotations

import json
import logging
import re
import time
import warnings
from datetime import datetime, timezone

from state import AutomateAnalysis, GraphState
from tools.enrichment_tools import EnrichmentToolbox
from agents.chain_analyzer import _analyze_deterministic

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL  # noqa: F401

logger = logging.getLogger(__name__)

_MAX_STEPS = 50  # garde-fou de la boucle de tool-calling

# ── Source réseau de la comparaison (décision : RDAP activé, BGP off) ─────────
# RDAP (whois) ON pour résoudre les org que MaxMind manque. BGP OFF (seuil 0.5 non
# calibré, invariance prouvée). ÉDITION DATÉE FIGÉE : A et B rejouent le MÊME
# net_cache (enrichment/data/net_cache_<date>.json) → déterminisme de la résolution.
# Doit être IDENTIQUE à l'édition utilisée pour régénérer les enriched.json de A.
RDAP_ENABLED = True
BGP_ENABLED = False
EDITION_DATE = "2026-06-16"


# ---------------------------------------------------------------------------
# Prompts système
# ---------------------------------------------------------------------------

_PROMPT_DET = """Tu es l'agent Analyzer d'un système de sécurité réseau SDN (LangGraph).

## Mission
Tu reçois le NOM d'une application dont on te donne les traces réseau BRUTES. Tu
produis le diagnostic en utilisant TES OUTILS — aucune donnée pré-annotée.

## Outils
- load_traces(app)            : liste TOUTES les destinations (IP) + stats brutes. EN PREMIER.
- resolve_asn(ip)             : ASN / organisation / réputation / self_loop d'une IP.
- classify_destination(ip)    : catégorie + flags + score d'une destination.
- reputation(ip)              : réputation seule.

## Procédure IMPÉRATIVE (couverture complète)
1. load_traces(app).
2. Pour CHAQUE destination listée : classify_destination(ip). N'OMETS AUCUNE IP.
3. Quand tout est classé, rédige une SYNTHÈSE finale (3-5 phrases) : comportement,
   menaces, risque global, contexte MITRE ATT&CK pertinent (ex. T1071 C2 over HTTP,
   T1041 exfiltration).

## Format final
Ton DERNIER message (sans appel d'outil) = uniquement le texte de la synthèse.
"""

_PROMPT_LLM = """Tu es l'agent Analyzer d'un système de sécurité réseau SDN (LangGraph).

## Mission
Tu reçois le NOM d'une application dont on te donne les traces réseau BRUTES. Tu dois
CLASSER toi-même chaque destination (IP) en catégorie de sécurité, en RAISONNANT à
partir des signaux bruts. Tu n'as PAS d'outil de classification : c'est TOI qui décides.

## Outils (signaux bruts seulement)
- load_traces(app) : liste TOUTES les destinations + stats brutes (bytes_total,
  distinct_ports, nb_flows, packets_total, protocols, hostname). EN PREMIER.
- resolve_asn(ip)  : ASN / organisation / réputation (trusted/untrusted/neutral/unknown)
  / self_loop (probabilité de boucle, signal worm/botnet).
- reputation(ip)   : réputation seule.

## Règles de classification À APPLIQUER (identiques au pipeline de référence)
Seuils : tau_dos = 1 000 000 octets ; port_scan_limit = 10 ports ; attack_limit = 0.8 (self_loop).
Réputation : trusted = org connue de confiance (google, amazon/aws, akamai, cloudflare,
microsoft/azure, apple, fastly, facebook/meta, netflix, oracle, ibm) ; untrusted = org
contenant bulletproof/anonymous/anonymizer/proxy ; neutral = org résolue non listée ;
unknown = non résolue.
Catégories (PRIORITÉ décroissante : botnet > worm > dos > port_scan > unsafe > monitored > safe) :
- botnet  : self_loop ≥ 0.8 ET reputation ∈ {untrusted, unknown}  → flags ["beaconing"],        score ≥ 6
- worm    : self_loop ≥ 0.8 ET reputation = neutral                → flags [],                    score ≥ 4
- dos     : bytes_total ≥ 1 000 000                                → flags ["syn_flood"],         score ≥ 4
- port_scan : distinct_ports ≥ 10                                  → flags ["port_scan"],         score ≥ 4
- unsafe  : reputation = untrusted                                 → flags ["data_exfiltration"], score ≥ 5
- monitored : reputation ∈ {neutral, unknown} SANS signal d'attaque → flags ["monitored"],       score = 2
- safe    : reputation = trusted, OU aucune autre catégorie        → flags [],                    score 0-3
PROTECTION : si reputation = trusted, ignore dos/port_scan SAUF si les DEUX sont présents.
(worm/botnet : uniquement si le DOT est de type ORG ; sinon ne les utilise pas.)

## Procédure
1. load_traces(app).
2. resolve_asn(ip) pour les IP dont tu as besoin du contexte (réputation/self_loop).
3. Classe CHAQUE destination. N'OMETS AUCUNE IP.
4. Réponds par un UNIQUE objet JSON (dernier message, sans appel d'outil), SANS texte autour :
{
  "global_risk_level": "low|medium|high|critical",
  "summary": "synthèse 3-5 phrases avec contexte MITRE ATT&CK",
  "destinations": [
    {"ip": "x.x.x.x", "category": "...", "flags": ["..."], "score": int, "reputation": "..."}
  ]
}
"""


# ---------------------------------------------------------------------------
# Boucle de tool-calling
# ---------------------------------------------------------------------------

def _invoke_with_retry(llm, messages, max_retries: int = 5):
    """invoke avec backoff sur rate-limit Groq (429) — utile en benchmark intensif."""
    delay = 5.0
    for attempt in range(max_retries):
        try:
            return llm.invoke(messages)
        except Exception as exc:
            msg = str(exc).lower()
            is_rate = "429" in msg or "rate" in msg or "too many" in msg
            if not is_rate or attempt == max_retries - 1:
                raise
            logger.warning("Rate-limit Groq — pause %.0fs (tentative %d/%d)",
                           delay, attempt + 1, max_retries)
            time.sleep(delay)
            delay *= 2
    raise RuntimeError("invoke_with_retry: épuisé")


def _run_tool_loop(app: str, box: EnrichmentToolbox, system_prompt: str,
                   include_classify: bool) -> tuple[str, int, int, int]:
    """Boucle agentique. Retourne (message_final, steps, llm_calls, tool_calls)."""
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
    from langchain_groq import ChatGroq

    tools = box.tools(include_classify=include_classify)
    tool_map = {t.name: t for t in tools}
    llm = ChatGroq(api_key=GROQ_API_KEY, model=WORKER_MODEL, temperature=0).bind_tools(tools)

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"Analyse l'application dont les traces brutes ont pour nom : {app}"),
    ]
    final = ""
    llm_calls = tool_calls = 0
    step = 0
    for step in range(1, _MAX_STEPS + 1):
        ai = _invoke_with_retry(llm, messages)
        llm_calls += 1
        messages.append(ai)
        calls = getattr(ai, "tool_calls", None) or []
        if not calls:
            final = (ai.content or "").strip()
            break
        for tc in calls:
            tool_calls += 1
            name = tc.get("name")
            args = tc.get("args", {}) or {}
            try:
                result = tool_map[name].invoke(args)
            except Exception as exc:
                result = {"error": str(exc)}
                logger.warning("Analyzer-B : outil %s(%s) a échoué : %s", name, args, exc)
            messages.append(ToolMessage(
                content=json.dumps(result, ensure_ascii=False, default=str),
                tool_call_id=tc.get("id"),
            ))
    return final, step, llm_calls, tool_calls


def _run_offline(app: str, box: EnrichmentToolbox) -> str:
    """Fallback SANS LLM (B-det seulement) : classe TOUTES les destinations."""
    box._load_traces(app)
    for ip in box.all_destination_ips():
        box._classify_destination(ip)
    return ""


# ---------------------------------------------------------------------------
# Assemblage
# ---------------------------------------------------------------------------

def _assemble_deterministic(app: str, box: EnrichmentToolbox, narrative: str):
    """B-det : assemble depuis les sorties d'outils (réutilise _analyze_deterministic)."""
    automate = {"automate_id": app, "app_name": app,
                "states": box.assemble_states(),
                "transitions": box.assemble_transitions()}
    analysis = _analyze_deterministic(automate)
    if narrative:
        analysis = analysis.model_copy(update={"llm_summary": narrative})
    return analysis, dict(box.decisions)


def _parse_llm_json(raw: str) -> dict | None:
    """Extrait l'objet JSON du message final B-llm (tolérant au markdown)."""
    if not raw:
        return None
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except Exception:
        return None


_VALID_FLAGS = {"monitored", "syn_flood", "port_scan", "data_exfiltration", "beaconing"}


def _assemble_llm(app: str, box: EnrichmentToolbox, raw: str):
    """B-llm : flags/score décidés par le LLM (ablation). Assemble une
    AutomateAnalysis comparable en réutilisant _analyze_deterministic sur des
    transitions dont suspicion.flags/score viennent du LLM."""
    data = _parse_llm_json(raw)
    decisions: dict[str, dict] = {}
    narrative = None
    if data:
        narrative = data.get("summary")
        for d in data.get("destinations", []) or []:
            ip = str(d.get("ip", "")).strip()
            if not ip or ip not in box._endpoints:
                continue  # IP inventée / hors périmètre → ignorée
            flags = [f for f in (d.get("flags") or []) if f in _VALID_FLAGS]
            try:
                score = int(d.get("score", 0))
            except (TypeError, ValueError):
                score = 0
            rep = d.get("reputation") or "unknown"
            decisions[ip] = {"category": d.get("category", "?"), "flags": sorted(flags),
                             "score": max(0, min(score, 10)), "reputation": rep}

    # Transitions à partir des décisions LLM (network info = vérité terrain CSV)
    transitions = []
    for idx, ip in enumerate(sorted(decisions), start=1):
        dec = decisions[ip]
        ep = box._endpoints[ip]
        port = sorted(ep.ports)[0] if ep.ports else None
        proto = sorted(ep.protocols)[0] if ep.protocols else "TCP"
        rep_json = dec["reputation"] if dec["reputation"] in ("trusted", "neutral") else (
            dec["reputation"] if dec["reputation"] in ("untrusted", "suspicious", "monitored", "unknown")
            else "unknown")
        # behavior.probability = self-loop DOT (STRUCTUREL, vérité terrain ; PAS une
        # décision LLM). On le fixe comme en A pour que le score global pondéré soit
        # comparable et ne reflète QUE les flags/score décidés par le LLM.
        info = box.resolved.get(ip) or box._resolve_one(ip)
        sl = info.get("self_loop", 0.0) or 0.0
        transitions.append({
            "id": f"t{idx:02d}", "from": "INITIAL", "to": ip,
            "label": f"{dec['category']} → {ip}",
            "network_call": {"ip": ip, "port": port, "protocol": proto, "hostname": ep.dstname},
            "service": {"name": ip, "type": "unknown", "reputation": rep_json},
            "suspicion": {"score": dec["score"], "flags": dec["flags"],
                          "notes": f"LLM: catégorie={dec['category']}"},
            "behavior": {"probability": round(sl, 3) if sl > 0 else 1.0},
        })
    automate = {"automate_id": app, "app_name": app,
                "states": box.assemble_states(), "transitions": transitions}
    analysis = _analyze_deterministic(automate)
    if narrative:
        analysis = analysis.model_copy(update={"llm_summary": narrative})
    return analysis, decisions


# ---------------------------------------------------------------------------
# Point d'entrée réutilisable (graphe ET benchmark)
# ---------------------------------------------------------------------------

def run_analyzer_b(app: str, assembly_mode: str = "deterministic",
                   enable_rdap: bool = RDAP_ENABLED, enable_bgp: bool = BGP_ENABLED,
                   edition_date: str | None = EDITION_DATE) -> dict:
    """Exécute l'Analyzer-B et retourne analyse + décisions + couverture + coût.

    Returns dict :
      automate_analysis, decisions {ip:{category,flags,score,reputation}},
      universe (list[ip] vérité terrain), coverage {total,classified,ratio,missed},
      source, assembly_mode, steps, llm_calls, tool_calls, elapsed_s
    """
    logger.info("═══ Analyzer-B (mode=%s) : app=%s ═══", assembly_mode, app)
    t0 = time.perf_counter()
    box = EnrichmentToolbox(enable_rdap=enable_rdap, enable_bgp=enable_bgp,
                            edition_date=edition_date)
    steps = llm_calls = tool_calls = 0

    if not GROQ_API_KEY:
        logger.warning("Analyzer-B : pas de clé Groq → fallback hors-ligne (B-det).")
        _run_offline(app, box)
        analysis, decisions = _assemble_deterministic(app, box, "")
        source = "no_llm_fallback"
    else:
        if assembly_mode == "deterministic":
            final, steps, llm_calls, tool_calls = _run_tool_loop(
                app, box, _PROMPT_DET, include_classify=True)
            if box.flows is None:
                box._load_traces(app)  # univers connu pour le rapport, même si LLM a échoué
            analysis, decisions = _assemble_deterministic(app, box, final)
        elif assembly_mode == "llm":
            final, steps, llm_calls, tool_calls = _run_tool_loop(
                app, box, _PROMPT_LLM, include_classify=False)
            if box.flows is None:
                box._load_traces(app)
            analysis, decisions = _assemble_llm(app, box, final)
        else:
            raise ValueError(f"assembly_mode inconnu : {assembly_mode!r}")
        source = "llm"

    elapsed = round(time.perf_counter() - t0, 2)
    universe = box.all_destination_ips()
    total = len(universe)
    classified = sum(1 for ip in decisions if ip in box._endpoints)
    missed = sorted(set(universe) - set(decisions))
    coverage = {"total": total, "classified": classified,
                "ratio": round(classified / total, 4) if total else 0.0, "missed": missed}

    logger.info("Analyzer-B : couverture %d/%d (%.0f%%), risque=%s, source=%s, %.1fs, "
                "%d LLM / %d outils",
                classified, total, 100 * coverage["ratio"],
                (analysis.risk_level if analysis else "?"), source, elapsed,
                llm_calls, tool_calls)
    if missed:
        logger.warning("Analyzer-B : %d IP NON couverte(s) : %s", len(missed), missed)

    return {"automate_analysis": analysis, "decisions": decisions, "universe": universe,
            "coverage": coverage, "source": source, "assembly_mode": assembly_mode,
            "steps": steps, "llm_calls": llm_calls, "tool_calls": tool_calls,
            "elapsed_s": elapsed}


# ---------------------------------------------------------------------------
# Enrichissement PAR L'ARCHITECTURE → JSON enrichi sur disque (schéma A)
# ---------------------------------------------------------------------------

def _box_to_enriched_json(app: str, box: EnrichmentToolbox, source: str,
                          narrative: str) -> dict:
    """Construit un JSON enrichi au MÊME schéma que enrichment.json_builder, mais
    produit par l'ARCHITECTURE (Analyzer-B), pas par le pipeline.

    N'inclut que les destinations EFFECTIVEMENT classées par l'agent (la couverture
    réelle de B). Le schéma est identique à celui lu par _analyze_deterministic /
    load_automate → évaluable et déployable SANS modification.
    """
    counts: dict[str, int] = {}
    for d in box.decisions.values():
        counts[d["category"]] = counts.get(d["category"], 0) + 1
    thr = box.thresholds
    return {
        "automate_id": app,
        "app_name": app,
        "app_version": "architecture-b-v1",
        "platform": "android",
        "description": f"Automate enrichi par l'ARCHITECTURE (Analyzer-B bind_tools) ({app})",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "states": box.assemble_states(),
        "transitions": box.assemble_transitions(),
        "metadata": {
            "source": "architecture (analyzer-b bind_tools + classifier tools)",
            "analyzer_b_source": source,                 # "llm" | "no_llm_fallback"
            "dot_label_type": box.graph.label_type if box.graph else "UNKNOWN",
            "csv_source": box.flows.source if box.flows else None,
            "asn_db_available": box.resolver.maxmind_available,
            "rdap_enabled": getattr(box.resolver, "enable_rdap", False),
            "bgp_enabled": getattr(box.resolver, "enable_bgp", False),
            "category_counts": counts,
            "coverage": box.coverage(),                   # couverture réelle de B
            "architecture_summary": narrative or None,    # narratif MITRE (traçabilité)
            "thresholds": {k: thr[k] for k in ("attack_limit", "port_scan_limit", "tau_dos")},
        },
    }


# Prompt d'un PAQUET (chunk) : conversation fraîche, focalisée sur une liste d'IP.
_PROMPT_CHUNK = """Tu es l'agent Analyzer d'un système de sécurité réseau SDN.
Les traces brutes sont déjà chargées. On te donne une LISTE de destinations (IP).

Ta seule tâche : pour CHAQUE IP de la liste, appelle l'outil classify_destination(ip).
N'OMETS AUCUNE IP. N'écris pas de synthèse, n'appelle pas load_traces : appelle
uniquement classify_destination (et resolve_asn si tu en as besoin).
"""

# Taille de paquet : assez petite pour qu'UNE requête reste bien < 12000 tokens/min
# (system+tools+historique d'un paquet). 20 destinations ≈ ~3k tokens crête.
_CHUNK_SIZE = 20


def _run_chunk(box, chunk_ips, llm, tool_map) -> tuple[int, int]:
    """Classe un PAQUET d'IP dans une conversation FRAÎCHE (historique non cumulé
    entre paquets). Retourne (llm_calls, tool_calls)."""
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
    messages = [
        SystemMessage(content=_PROMPT_CHUNK),
        HumanMessage(content="Destinations à classer (classify_destination pour CHACUNE) :\n"
                     + "\n".join(chunk_ips)),
    ]
    llm_calls = tool_calls = 0
    for _ in range(_MAX_STEPS):
        ai = _invoke_with_retry(llm, messages)
        llm_calls += 1
        messages.append(ai)
        calls = getattr(ai, "tool_calls", None) or []
        if not calls:
            break
        for tc in calls:
            tool_calls += 1
            name = tc.get("name")
            args = tc.get("args", {}) or {}
            try:
                result = tool_map[name].invoke(args)
            except Exception as exc:
                result = {"error": str(exc)}
                logger.warning("chunk : outil %s(%s) a échoué : %s", name, args, exc)
            messages.append(ToolMessage(
                content=json.dumps(result, ensure_ascii=False, default=str),
                tool_call_id=tc.get("id")))
    return llm_calls, tool_calls


def _summarize_b(app: str, box, llm) -> str:
    """Synthèse MITRE finale APRÈS fusion (1 appel LLM compact ; repli déterministe).
    Contexte minimal (counts + quelques suspectes) → reste largement sous la limite."""
    from langchain_core.messages import HumanMessage, SystemMessage
    counts: dict[str, int] = {}
    susp = []
    for ip, d in box.decisions.items():
        counts[d["category"]] = counts.get(d["category"], 0) + 1
        if d["flags"] or d["score"] >= 4:
            susp.append(f"{ip}: {d['category']} flags={d['flags']} score={d['score']}")
    ctx = (f"Application {app}. Répartition des catégories : {counts}. "
           f"Destinations notables :\n" + ("\n".join(susp[:15]) or "(aucune)"))
    try:
        resp = _invoke_with_retry(llm, [
            SystemMessage(content="Rédige une synthèse de sécurité de 3-5 phrases "
                          "(comportement, menaces, risque global, contexte MITRE ATT&CK). "
                          "Texte seul, pas de JSON."),
            HumanMessage(content=ctx)])
        return (resp.content or "").strip()
    except Exception as exc:
        logger.warning("Synthèse B échouée (%s) — résumé déterministe.", exc)
        return (f"Enrichissement par l'architecture de {app} : catégories {counts}. "
                f"{len(susp)} destination(s) notable(s).")


def enrich_app_b(app: str, enable_rdap: bool = RDAP_ENABLED,
                 enable_bgp: bool = BGP_ENABLED,
                 edition_date: str | None = EDITION_DATE,
                 chunk_size: int = _CHUNK_SIZE) -> dict:
    """L'ARCHITECTURE enrichit elle-même `app` (Analyzer-B, bind_tools) et retourne
    un JSON enrichi complet (schéma A) + métriques.

    CHUNKING : les destinations sont découpées en paquets de ``chunk_size`` ; chaque
    paquet = une requête LLM FRAÎCHE (l'historique ne s'accumule pas entre paquets →
    pas d'explosion de taille sur les grosses apps). Les résultats sont fusionnés dans
    le même ``box`` ; le score global et l'agrégation se font UNE fois, à l'assemblage
    final (résultat identique à un enrichissement en un bloc).

    Repli hors-ligne (couverture pleine, déterministe) si pas de clé Groq. Backoff
    rate-limit conservé (_invoke_with_retry). Schéma de sortie identique à A.

    Returns: {enriched, coverage, source, n_chunks, llm_calls, tool_calls, elapsed_s}
    """
    logger.info("═══ Enrichissement PAR L'ARCHITECTURE : app=%s ═══", app)
    t0 = time.perf_counter()
    box = EnrichmentToolbox(enable_rdap=enable_rdap, enable_bgp=enable_bgp,
                            edition_date=edition_date)
    llm_calls = tool_calls = 0
    narrative = ""

    # Chargement des traces (I/O ; la classification reste pilotée par le LLM).
    box._load_traces(app)
    ips = box.all_destination_ips()
    chunks = [ips[i:i + chunk_size] for i in range(0, len(ips), chunk_size)]
    n_chunks = len(chunks)

    if not GROQ_API_KEY:
        logger.warning("enrich_app_b : pas de clé Groq → repli hors-ligne (couverture pleine).")
        for ip in ips:
            box._classify_destination(ip)
        source = "no_llm_fallback"
        n_chunks = 0
    else:
        from langchain_groq import ChatGroq
        tools = box.tools(include_classify=True)
        tool_map = {t.name: t for t in tools}
        llm = ChatGroq(api_key=GROQ_API_KEY, model=WORKER_MODEL,
                       temperature=0).bind_tools(tools)
        for i, chunk in enumerate(chunks, 1):
            logger.info("  paquet %d/%d (%d destinations)", i, n_chunks, len(chunk))
            lc, tc = _run_chunk(box, chunk, llm, tool_map)
            llm_calls += lc
            tool_calls += tc
        narrative = _summarize_b(app, box, llm)
        llm_calls += 1  # l'appel de synthèse
        source = "llm"

    enriched = _box_to_enriched_json(app, box, source, narrative)
    cov = box.coverage()
    elapsed = round(time.perf_counter() - t0, 2)
    logger.info("enrich_app_b : %s → %d/%d destinations (%.0f%%), source=%s, paquets=%d, "
                "%d LLM / %d outils, %.1fs",
                app, cov["classified"], cov["total"], 100 * cov["ratio"],
                source, n_chunks, llm_calls, tool_calls, elapsed)
    return {"enriched": enriched, "coverage": cov, "source": source,
            "n_chunks": n_chunks, "llm_calls": llm_calls, "tool_calls": tool_calls,
            "elapsed_s": elapsed}


# ---------------------------------------------------------------------------
# Nœud LangGraph (Condition B)
# ---------------------------------------------------------------------------

def chain_analyzer_b_node(state: GraphState) -> dict:
    """Nœud Analyzer-B : lit ``state.raw_app`` + ``state.assembly_mode`` et produit
    une ``AutomateAnalysis`` via tool-calling. Idempotent."""
    if state.automate_analysis is not None:
        logger.info("Analyzer-B : automate déjà analysé — passage de la main")
        return {}
    raw_app = getattr(state, "raw_app", None)
    if not raw_app:
        logger.error("Analyzer-B : state.raw_app vide — rien à analyser")
        return {}

    mode = getattr(state, "assembly_mode", "deterministic") or "deterministic"
    out = run_analyzer_b(raw_app, assembly_mode=mode)
    analysis = out["automate_analysis"]
    if analysis is None:
        return {}
    return {"automate_analysis": analysis, "analyzer_b_report": {
        "coverage": out["coverage"], "source": out["source"],
        "assembly_mode": out["assembly_mode"], "steps": out["steps"],
        "llm_calls": out["llm_calls"], "tool_calls": out["tool_calls"],
        "elapsed_s": out["elapsed_s"]}}
