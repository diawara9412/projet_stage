"""
agents/chain_analyzer.py — Agent ChainAnalyzer du système Phase 2.

Lit un automate JSON, identifie les comportements suspects et les services
légitimes, calcule un score de risque global, et produit une AutomateAnalysis
stockée dans le GraphState pour être consommée par le ChainGenerator.

Flux de traitement
------------------
1. Chargement de l'automate via l'outil ``load_automate`` (déterministe).
2. Analyse déterministe : extraction des transitions suspectes, des services
   légitimes, calcul du score pondéré et des recommandations.
3. Enrichissement LLM (optionnel) : résumé narratif et affinement des
   recommandations si GROQ_API_KEY est disponible.
"""

import json
import logging
import re
import warnings
from datetime import datetime, timezone

from tools.chain_tools import load_automate
from state import AutomateAnalysis, GraphState, LegitimateService, SuspiciousTransition

with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from config import GROQ_API_KEY, WORKER_MODEL, WORKER_TEMPERATURE

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

CHAIN_ANALYZER_SYSTEM_PROMPT = """Tu es l'agent ChainAnalyzer d'un système de sécurité réseau SDN basé sur LangGraph.

## Ta mission

Analyser un automate réseau enrichi (comportement d'une application mobile) et produire une analyse de sécurité structurée qui servira à générer une chaîne de protection (firewall + IDS + IPS).

## Ce que tu reçois

Un résumé de l'analyse déterministe d'un automate : score global, transitions suspectes avec leurs flags, services légitimes identifiés.

## Ce que tu dois produire

Un objet JSON STRICT avec exactement ces deux champs :

```json
{
  "llm_summary": "Résumé narratif de 3 à 5 phrases expliquant le comportement de l'application, les menaces identifiées et le niveau de risque global.",
  "recommended_actions": [
    "Action concrète 1 pour le ChainGenerator (ex: BLOCK IP:x.x.x.x PORT:9001 — raison)",
    "Action concrète 2",
    "..."
  ]
}
```

## Règles

- Réfère-toi aux IPs, ports et flags spécifiques de l'analyse.
- Les recommended_actions doivent être actionnables par un générateur de règles (format : TYPE — DETAIL — RAISON).
- Ne répète pas mot pour mot les notes déterministes, apporte du contexte MITRE ATT&CK ou de la threat intelligence.
- Réponds UNIQUEMENT avec le JSON, sans markdown ni texte autour.
"""

# ---------------------------------------------------------------------------
# Tables de correspondance (déterministes)
# ---------------------------------------------------------------------------

_FLAG_TO_CATEGORY: dict[str, str] = {
    "known_c2":            "c2_active",
    "tor_exit_node":       "tor_communication",
    "beaconing":           "c2_beaconing",
    "data_exfiltration":   "data_exfiltration",
    "dga_domain":          "dga_domain",
    "bulletproof_hosting": "suspicious_hosting",
    "suspicious_path":     "suspicious_endpoint",
    "self_signed_cert":    "invalid_certificate",
    "geo_anomaly":         "geo_anomaly",
    "port_scan":           "port_scan",
}

_FLAG_PRIORITY: list[str] = [
    "known_c2", "tor_exit_node", "beaconing",
    "data_exfiltration", "dga_domain", "bulletproof_hosting",
    "suspicious_path", "self_signed_cert", "geo_anomaly", "port_scan",
]


def _infer_risk_category(flags: list[str]) -> str:
    for flag in _FLAG_PRIORITY:
        if flag in flags:
            return _FLAG_TO_CATEGORY[flag]
    return "generic_suspicious"


def _score_to_risk(score: float) -> str:
    if score <= 2.0:
        return "low"
    if score <= 5.0:
        return "medium"
    if score <= 8.0:
        return "high"
    return "critical"


def _derive_recommended_actions(
    suspicious: list[SuspiciousTransition],
    legit: list[LegitimateService],
    global_score: float,
) -> list[str]:
    """Génère des recommandations concrètes pour le ChainGenerator."""
    actions: list[str] = []
    seen_ips: set[str] = set()

    for t in suspicious:
        ip = t.dst_ip
        port = t.dst_port
        proto = t.protocol

        if "known_c2" in t.flags or "tor_exit_node" in t.flags:
            if ip not in seen_ips:
                actions.append(
                    f"FIREWALL BLOCK priorité=900 — {ip}:{port}/{proto} "
                    f"(C2/Tor détecté, transition {t.transition_id})"
                )
                seen_ips.add(ip)
            if "beaconing" in t.flags:
                actions.append(
                    f"IDS SIGNATURE beaconing — {ip}:{port}/{proto} "
                    f"seuil={t.flags} (transition {t.transition_id})"
                )

        elif "beaconing" in t.flags and ip not in seen_ips:
            actions.append(
                f"IDS SIGNATURE beaconing — {ip}:{port}/{proto} "
                f"(heartbeat C2, transition {t.transition_id})"
            )
            actions.append(
                f"IPS ACTION rate_limit — {ip}:{port}/{proto} max=10req/min "
                f"(transition {t.transition_id})"
            )
            seen_ips.add(ip)

        elif "data_exfiltration" in t.flags and ip not in seen_ips:
            actions.append(
                f"FIREWALL BLOCK priorité=800 — {ip}:{port}/{proto} "
                f"(exfiltration de données, transition {t.transition_id})"
            )
            actions.append(
                f"IDS SIGNATURE data_exfiltration — sortant vers {ip} "
                f"seuil=50000B (transition {t.transition_id})"
            )
            seen_ips.add(ip)

        elif "dga_domain" in t.flags and ip not in seen_ips:
            actions.append(
                f"IDS SIGNATURE dga_domain — {ip}:{port}/{proto} "
                f"(domaine généré algorithmiquement, transition {t.transition_id})"
            )
            seen_ips.add(ip)

        elif ip not in seen_ips:
            actions.append(
                f"FIREWALL LOG — {ip}:{port}/{proto} score={t.suspicion_score} "
                f"(transition {t.transition_id})"
            )
            seen_ips.add(ip)

    # Services légitimes → allow explicite
    for svc in legit:
        ips_str = ", ".join(svc.ips[:3])
        ports_str = ", ".join(str(p) for p in svc.ports[:3])
        actions.append(
            f"FIREWALL ALLOW priorité=100 — {svc.name} "
            f"IPs=[{ips_str}] ports=[{ports_str}] ({svc.service_type})"
        )

    if global_score >= 7.0:
        actions.append(
            "IPS ACTION quarantine — Activer le mode défensif renforcé "
            f"(score global={global_score:.1f}/10)"
        )

    return actions


# ---------------------------------------------------------------------------
# Analyse déterministe
# ---------------------------------------------------------------------------

def _analyze_deterministic(automate: dict) -> AutomateAnalysis:
    """Analyse complète sans LLM — extraction directe des champs JSON."""
    transitions = automate.get("transitions", [])
    states = automate.get("states", [])

    suspicious: list[SuspiciousTransition] = []
    for t in transitions:
        susp = t.get("suspicion", {})
        score = int(susp.get("score", 0))
        flags = susp.get("flags", [])
        if score >= 4 or flags:
            nc = t.get("network_call", {})
            suspicious.append(SuspiciousTransition(
                transition_id=t.get("id", "?"),
                from_state=t.get("from", "?"),
                to_state=t.get("to", "?"),
                label=t.get("label", ""),
                dst_ip=nc.get("ip") or "unknown",
                dst_port=int(nc.get("port") or 0),
                protocol=nc.get("protocol") or "unknown",
                suspicion_score=score,
                flags=flags,
                risk_category=_infer_risk_category(flags),
                explanation=susp.get("notes") or "",
            ))

    # ── ENRICHISSEMENT PAR LES OUTILS (proactif ET réactif, même code) ───────────
    # threat_intel (fichier réputation) + VirusTotal + réputation ASN/org : une
    # destination flaguée par N'IMPORTE QUEL outil devient SUSPECTE (→ BLOCK).
    tool_bad: dict[str, str] = {}
    try:
        from enrichment import virustotal
        from enrichment.asn_resolver import AsnResolver
        from enrichment.classifier import reputation_state
        from whitelist import threat_intel
        resolver = AsnResolver()
        for _ip in {(t.get("network_call") or {}).get("ip") for t in transitions}:
            if not _ip:
                continue
            if threat_intel.reputation(_ip) == "malicious":
                tool_bad[_ip] = "threat-intel (C2 connu/appris)"
            elif virustotal.available() and virustotal.is_malicious_ip(_ip):
                tool_bad[_ip] = "VirusTotal"
            elif reputation_state(resolver.resolve(_ip)) == "untrusted":
                tool_bad[_ip] = "reputation ASN/org douteuse"
    except Exception:
        pass
    for t in transitions:
        nc = t.get("network_call", {})
        ip = nc.get("ip")
        if ip in tool_bad and not any(s.dst_ip == ip for s in suspicious):
            suspicious.append(SuspiciousTransition(
                transition_id=t.get("id", "?"), from_state=t.get("from", "?"),
                to_state=t.get("to", "?"), label=t.get("label", ""),
                dst_ip=ip, dst_port=int(nc.get("port") or 0),
                protocol=nc.get("protocol") or "unknown",
                suspicion_score=10, flags=["tool-flagged"],
                risk_category="c2", explanation=f"Outil : {tool_bad[ip]} -> malveillant"))

    # Regroupement des services légitimes par nom
    services_map: dict[str, LegitimateService] = {}
    for t in transitions:
        svc = t.get("service", {})
        if svc.get("reputation") not in ("trusted", "neutral"):
            continue
        if (t.get("network_call") or {}).get("ip") in tool_bad:
            continue                            # flaguee par un outil → hors des legitimes
        name = svc.get("name") or "unknown"
        nc = t.get("network_call", {})
        ip = nc.get("ip")
        port = nc.get("port")
        proto = nc.get("protocol")
        if name not in services_map:
            services_map[name] = LegitimateService(
                name=name,
                service_type=svc.get("type") or "unknown",
                ips=[],
                ports=[],
                transition_ids=[],
                protocol=(proto or None),
            )
        s = services_map[name]
        # Conserve le protocole du service (1er non vide) — utile pour les services
        # connectionless (UDP/ICMP) que l'ancien défaut « tout TCP » écrasait.
        if s.protocol is None and proto:
            s.protocol = proto
        if ip and ip not in s.ips:
            s.ips.append(ip)
        if port and int(port) not in s.ports:
            s.ports.append(int(port))
        s.transition_ids.append(t.get("id", "?"))

    # Score global pondéré par la probabilité de chaque transition
    probs = [t.get("behavior", {}).get("probability", 1.0) for t in transitions]
    scores = [t.get("suspicion", {}).get("score", 0) for t in transitions]
    total_weight = sum(probs) or 1.0
    global_score = sum(s * p for s, p in zip(scores, probs)) / total_weight

    risk_level = _score_to_risk(global_score)
    legit_services = list(services_map.values())
    recommended = _derive_recommended_actions(suspicious, legit_services, global_score)

    return AutomateAnalysis(
        automate_id=automate.get("automate_id", "unknown"),
        app_name=automate.get("app_name", "unknown"),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        global_suspicion_score=round(global_score, 2),
        risk_level=risk_level,
        nb_states=len(states),
        nb_transitions=len(transitions),
        nb_suspicious=len(suspicious),
        suspicious_transitions=suspicious,
        legitimate_services=legit_services,
        recommended_actions=recommended,
        llm_summary=None,
    )


# ---------------------------------------------------------------------------
# Enrichissement LLM
# ---------------------------------------------------------------------------

def _enrich_with_llm(analysis: AutomateAnalysis) -> AutomateAnalysis:
    """Ajoute un résumé narratif et affine les recommandations via Llama."""
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_groq import ChatGroq

        llm = ChatGroq(
            api_key=GROQ_API_KEY,
            model=WORKER_MODEL,
            temperature=0.1,  # déterministe pour la sécurité
        )

        susp_summary = "\n".join(
            f"  - [{t.transition_id}] {t.label} → {t.dst_ip}:{t.dst_port}/{t.protocol} "
            f"score={t.suspicion_score}/10 flags={t.flags}"
            for t in analysis.suspicious_transitions
        ) or "  (aucune)"

        legit_summary = "\n".join(
            f"  - {s.name} ({s.service_type}) IPs={s.ips[:2]}"
            for s in analysis.legitimate_services
        ) or "  (aucun)"

        context = f"""Application analysée : {analysis.app_name} (id: {analysis.automate_id})
Score global : {analysis.global_suspicion_score}/10 — Niveau de risque : {analysis.risk_level}
États : {analysis.nb_states} | Transitions : {analysis.nb_transitions} | Suspectes : {analysis.nb_suspicious}

Transitions suspectes :
{susp_summary}

Services légitimes identifiés :
{legit_summary}

Recommandations déterministes générées :
{chr(10).join('  - ' + a for a in analysis.recommended_actions[:5])}

Produis le JSON demandé (llm_summary + recommended_actions enrichies)."""

        response = llm.invoke([
            SystemMessage(content=CHAIN_ANALYZER_SYSTEM_PROMPT),
            HumanMessage(content=context),
        ])

        raw = response.content.strip()
        # Extraire le JSON même s'il est encadré de markdown
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if not m:
            logger.warning("LLM n'a pas retourné de JSON valide — conservation de l'analyse déterministe")
            return analysis

        data = json.loads(m.group())
        llm_summary = data.get("llm_summary")
        llm_actions = data.get("recommended_actions")

        updates: dict = {}
        if llm_summary:
            updates["llm_summary"] = llm_summary
        if llm_actions and isinstance(llm_actions, list):
            # Fusionne : actions déterministes + actions LLM supplémentaires (dédupliquées)
            existing_set = set(analysis.recommended_actions)
            extras = [a for a in llm_actions if a not in existing_set]
            updates["recommended_actions"] = analysis.recommended_actions + extras

        if updates:
            return analysis.model_copy(update=updates)

    except Exception as exc:
        logger.warning("Enrichissement LLM échoué : %s — analyse déterministe conservée", exc)

    return analysis


# ---------------------------------------------------------------------------
# Nœud principal
# ---------------------------------------------------------------------------

def chain_analyzer_node(state: GraphState) -> dict:
    """Nœud ChainAnalyzer du graphe LangGraph Phase 2.

    Charge l'automate depuis ``state.automate_path``, analyse les comportements
    suspects et les services légitimes, puis stocke une ``AutomateAnalysis``
    dans le GraphState.

    Idempotent : si ``state.automate_analysis`` est déjà rempli, ne refait
    pas l'analyse.

    Args:
        state: État courant du graphe.

    Returns:
        dict: ``{"automate_analysis": AutomateAnalysis}`` si réussi,
              ``{}`` si l'automate est déjà analysé ou si une erreur survient.
    """
    logger.info("═══ ChainAnalyzer : démarrage ═══")

    # Idempotence
    if state.automate_analysis is not None:
        logger.info(
            "Automate '%s' déjà analysé — passage de la main",
            state.automate_analysis.automate_id,
        )
        return {}

    # Vérification du chemin
    if not state.automate_path:
        logger.error("ChainAnalyzer : state.automate_path est vide — impossible d'analyser")
        return {}

    # Chargement de l'automate
    load_result = load_automate.invoke({"path": state.automate_path})
    if load_result.get("status") != "success":
        logger.error("ChainAnalyzer : chargement échoué — %s", load_result.get("message"))
        return {}

    automate = load_result["automate"]
    logger.info(
        "Automate chargé : '%s' (%d états, %d transitions)",
        automate.get("app_name", automate["automate_id"]),
        load_result["nb_states"],
        load_result["nb_transitions"],
    )

    # Analyse déterministe (toujours exécutée)
    analysis = _analyze_deterministic(automate)
    logger.info(
        "Analyse déterministe : score=%.2f (%s), suspects=%d, légitimes=%d",
        analysis.global_suspicion_score,
        analysis.risk_level,
        analysis.nb_suspicious,
        len(analysis.legitimate_services),
    )

    # Enrichissement LLM (optionnel)
    if GROQ_API_KEY:
        logger.info("Enrichissement LLM en cours...")
        analysis = _enrich_with_llm(analysis)
        if analysis.llm_summary:
            logger.info("LLM summary : %s", analysis.llm_summary[:120])
    else:
        logger.info("GROQ_API_KEY absente — mode fallback déterministe complet")

    logger.info("═══ ChainAnalyzer : terminé ═══")
    return {"automate_analysis": analysis}
