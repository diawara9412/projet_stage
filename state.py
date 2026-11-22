"""
state.py — Structure de données partagée entre tous les agents LangGraph.

Définit le GraphState (état Pydantic central), les sous-modèles métier,
et la fonction merge_state_updates pour fusionner les mises à jour partielles
retournées par chaque nœud du graphe.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Type alias exporté — utilisé dans GraphState et SupervisorDecision
# ---------------------------------------------------------------------------

AgentName = Literal[
    "topology_designer",
    "traffic_generator",
    "attack_simulator",
    "end",
]

# ---------------------------------------------------------------------------
# Champs accumulatifs : append au lieu de remplacer dans merge_state_updates
# ---------------------------------------------------------------------------

_ACCUMULATIVE_FIELDS: frozenset[str] = frozenset({
    "generated_traffic_flows",
    "attack_scenarios",
    "network_observations",
    "supervisor_decisions",
})


# ---------------------------------------------------------------------------
# Sous-modèles
# ---------------------------------------------------------------------------

class DeployedTopology(BaseModel):
    """Informations sur la topologie déployée dans Mininet."""

    topology_name: str
    nb_hosts: int
    nb_switches: int
    nb_links: int
    hosts: list[str]
    host_ips: dict[str, str]
    deployed_at: str  # timestamp ISO 8601


class TrafficFlow(BaseModel):
    """Un flux de trafic légitime généré par le TrafficGenerator."""

    flow_type: str           # "http" | "iperf" | "dns"
    source: str              # nom du host source (ex. "h0")
    destination: str         # nom du host destination (ex. "h1")
    duration_s: float
    metrics: dict            # bytes envoyés, débit, nb requêtes, etc.


class AttackScenario(BaseModel):
    """Une attaque injectée par l'AttackSimulator."""

    attack_type: str         # "syn_flood" | "port_scan"
    attacker: str            # host attaquant (ex. "h0")
    victim: str | None = None           # host victime (syn_flood)
    target_subnet: str | None = None    # sous-réseau ciblé (port_scan)
    duration_s: float
    metrics: dict            # paquets envoyés, ports ouverts détectés, etc.


class NetworkObservation(BaseModel):
    """Mesure de l'état du réseau à un instant donné (avant/pendant attaque)."""

    timestamp: str           # ISO 8601
    victim: str              # host mesuré
    loss_percent: float      # % de paquets perdus (ICMP)
    avg_rtt_ms: float        # RTT moyen en ms (-1 si unreachable)
    assessment: str          # "normal" | "degraded" | "unreachable"


class SupervisorDecision(BaseModel):
    """Trace d'une décision prise par le Supervisor à chaque tour."""

    turn: int
    agent_called: AgentName
    reasoning: str           # justification textuelle (issue du LLM ou règle dure)
    iteration_count: int     # valeur de iteration_count au moment de la décision


# ---------------------------------------------------------------------------
# Sous-modèles Phase 2 — Chaînes de sécurité
# ---------------------------------------------------------------------------

class SuspiciousTransition(BaseModel):
    """Une transition suspecte extraite d'un automate par le ChainAnalyzer."""

    transition_id: str
    from_state: str
    to_state: str
    label: str
    dst_ip: str
    dst_port: int
    protocol: str
    suspicion_score: int        # 0–10
    flags: list[str]
    risk_category: str          # "c2_beaconing" | "tor_communication" | "data_exfiltration" | ...
    explanation: str


class LegitimateService(BaseModel):
    """Un service légitime identifié dans un automate réseau."""

    name: str
    service_type: str           # "API" | "CDN" | "payment" | "analytics" | ...
    ips: list[str]
    ports: list[int]
    transition_ids: list[str]   # IDs des transitions associées à ce service
    protocol: str | None = None  # proto du service (UDP/TCP/ICMP) ; None → ancien comportement (TCP par défaut)


class AutomateAnalysis(BaseModel):
    """Résultat complet produit par le ChainAnalyzer sur un automate JSON.

    Sert de pivot entre ChainAnalyzer et ChainGenerator : toutes les
    informations nécessaires pour générer une chaîne de sécurité sont ici.
    """

    automate_id: str
    app_name: str
    analyzed_at: str                                    # ISO 8601
    global_suspicion_score: float                       # 0.0–10.0 (moyenne pondérée)
    risk_level: str                                     # "low" | "medium" | "high" | "critical"
    nb_states: int
    nb_transitions: int
    nb_suspicious: int
    suspicious_transitions: list[SuspiciousTransition] = Field(default_factory=list)
    legitimate_services: list[LegitimateService] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    llm_summary: str | None = None                      # narrative LLM, None en mode fallback


# ---------------------------------------------------------------------------
# Sous-modèles Phase 2 — Chaîne de sécurité (sortie du ChainGenerator)
# ---------------------------------------------------------------------------

class FirewallRule(BaseModel):
    """Une règle de pare-feu générée pour un switch OVS."""

    id: str                                              # ex: "FW-001"
    action: Literal["BLOCK", "ALLOW", "ALLOW_AND_INSPECT"]
    direction: Literal["inbound", "outbound", "both"]
    dst_ip: str | None = None                           # IP destination ou None (= any)
    dst_port: int | None = None                         # Port ou None (= any)
    protocol: Literal["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "any", "ARP"]
    priority: int                                        # 0–1000, plus haut = plus prioritaire
    source_transition_id: str | None = None             # transition automate déclencheuse
    comment: str


class IdsSignature(BaseModel):
    """Une signature de détection d'intrusion (IDS)."""

    id: str                                              # ex: "IDS-001"
    name: str                                            # ex: "C2_BEACONING_DETECTION"
    pattern_type: Literal[
        "beaconing", "data_exfiltration", "port_scan",
        "syn_flood", "dga_dns", "tor_communication", "suspicious_url",
        "monitored",
    ]
    match_criteria: dict                                 # critères de correspondance (ip, port, seuils...)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    source_transition_id: str | None = None
    comment: str


class IpsAction(BaseModel):
    """Une action automatique déclenchée par une signature IDS."""

    id: str                                              # ex: "IPS-001"
    on_signature: str                                    # référence à IdsSignature.id
    action: Literal["DROP_SOURCE", "RATE_LIMIT", "ALERT_ONLY", "QUARANTINE", "REDIRECT_HONEYPOT"]
    duration_seconds: int | None = None                  # None = permanent
    rate_limit_pps: int | None = None                    # paquets/s max (pour RATE_LIMIT)
    comment: str


class SecurityChain(BaseModel):
    """Chaîne de sécurité complète produite par le ChainGenerator.

    Contient les règles firewall, signatures IDS et actions IPS prêtes
    à être déployées par le PolicyEnforcer via le contrôleur Ryu sur OVS.
    """

    chain_id: str                                        # ex: "chain_pokemon_go_v1"
    source_automate_id: str                              # automate_id de l'AutomateAnalysis source
    source_app_name: str
    generated_at: str                                    # ISO 8601
    global_risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    ids_signatures: list[IdsSignature] = Field(default_factory=list)
    ips_actions: list[IpsAction] = Field(default_factory=list)
    deployment_target: dict = Field(default_factory=dict)
    generation_summary: str


# ---------------------------------------------------------------------------
# Sous-modèles Phase 2 — Rapport de validation (sortie du ChainValidator)
# ---------------------------------------------------------------------------

class ValidationIssue(BaseModel):
    """Un problème détecté dans une SecurityChain par le ChainValidator."""

    severity: Literal["ERROR", "WARNING", "INFO"]
    category: Literal[
        "conflict", "redundancy", "orphan_reference",
        "missing_field", "priority_issue", "best_practice",
    ]
    message: str
    affected_rule_ids: list[str] = Field(default_factory=list)
    suggested_fix: str | None = None


class ValidationReport(BaseModel):
    """Rapport complet produit par le ChainValidator sur une SecurityChain.

    Accompagne toujours la SecurityChain corrigée : les redondances ont été
    supprimées, les autres problèmes sont documentés ici pour le PolicyEnforcer.
    """

    chain_id: str
    validated_at: str                                    # ISO 8601
    is_valid: bool                                       # True si aucune ERROR
    quality_score: int                                   # 0–100
    issues: list[ValidationIssue] = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)
    validation_summary: str


# ---------------------------------------------------------------------------
# Sous-modèles Phase 2 — Résultat de déploiement (sortie du PolicyEnforcer)
# ---------------------------------------------------------------------------

class DeploymentResult(BaseModel):
    """Résultat du déploiement d'une SecurityChain par le PolicyEnforcer.

    Produit après l'appel REST à firewall_app.py.  Contient la trace complète
    du déploiement pour audit et pour les étapes suivantes du pipeline.
    """

    deployment_id: str                                   # ex: "deploy_pokemon_go_2026-05-30T18:00:00"
    chain_id: str                                        # référence à SecurityChain.chain_id
    deployed_at: str                                     # ISO 8601
    status: Literal["SUCCESS", "PARTIAL", "FAILED"]
    target_endpoint: str                                 # ex: "http://127.0.0.1:8080/firewall"
    http_status_code: int | None = None                  # code HTTP de la réponse firewall_app
    response_body: dict | None = None                    # réponse brute JSON de firewall_app
    rules_attempted: int                                 # nombre total de règles dans la chaîne
    rules_installed: int                                 # nombre de règles hardware_installed=True
    connected_switches: list[str] = Field(default_factory=list)
    deployment_errors: list[str] = Field(default_factory=list)
    deployment_summary: str


# ---------------------------------------------------------------------------
# État principal du graphe
# ---------------------------------------------------------------------------

class GraphState(BaseModel):
    """État partagé entre tous les agents du système multi-agents SDN.

    Cet objet est le seul canal de communication entre les nœuds LangGraph.
    Chaque agent lit l'état courant et retourne un dict partiel de mises à
    jour, fusionné par merge_state_updates (ou par le reducer LangGraph).

    Attributes:
        user_request: Demande en langage naturel de l'utilisateur.
        target_topology_hint: Indication optionnelle sur la taille souhaitée
            ("small", "medium", "large").
        requested_attacks: Liste des attaques demandées par l'utilisateur
            (ex. ["syn_flood", "port_scan"]).
        deployed_topology: Topologie Mininet active, remplie par TopologyDesigner.
        generated_traffic_flows: Flux légitimes accumulés par TrafficGenerator.
        attack_scenarios: Attaques accumulées par AttackSimulator.
        network_observations: Mesures d'impact accumulées.
        supervisor_decisions: Historique des décisions du Supervisor.
        iteration_count: Nombre d'itérations écoulées (incrémenté par Supervisor).
        max_iterations: Limite de sécurité anti-boucle infinie.
        next_agent: Prochain agent à invoquer (routage LangGraph).
        final_pcap_path: Chemin vers le fichier PCAP final (si capture lancée).
        simulation_report: Rapport Markdown généré en fin de simulation.
    """

    # --- Inputs (immuables après initialisation) ---
    user_request: str
    target_topology_hint: str | None = None
    requested_attacks: list[str] = Field(default_factory=list)

    # --- Travail en cours (accumulés par les workers) ---
    deployed_topology: DeployedTopology | None = None
    generated_traffic_flows: list[TrafficFlow] = Field(default_factory=list)
    attack_scenarios: list[AttackScenario] = Field(default_factory=list)
    network_observations: list[NetworkObservation] = Field(default_factory=list)
    supervisor_decisions: list[SupervisorDecision] = Field(default_factory=list)

    # --- Orchestration ---
    iteration_count: int = 0
    max_iterations: int = 5
    next_agent: AgentName = "topology_designer"

    # --- Sortie finale (Phase 1) ---
    final_pcap_path: str | None = None
    simulation_report: str | None = None

    # --- Phase 2 — Chaînes de sécurité ---
    automate_path: str | None = None                    # chemin vers l'automate JSON à analyser
    automate_analysis: AutomateAnalysis | None = None   # résultat du ChainAnalyzer
    security_chain: SecurityChain | None = None         # chaîne générée par le ChainGenerator
    validation_report: ValidationReport | None = None   # rapport du ChainValidator
    deployment_result: DeploymentResult | None = None   # résultat du PolicyEnforcer


# ---------------------------------------------------------------------------
# Utilitaire de fusion d'état
# ---------------------------------------------------------------------------

def merge_state_updates(state: GraphState, updates: dict) -> GraphState:
    """Fusionne un dict de mises à jour partielles dans l'état courant.

    Pour les champs listés dans ``_ACCUMULATIVE_FIELDS``, les nouveaux
    éléments sont ajoutés (append) à la liste existante plutôt que de la
    remplacer.  Pour tous les autres champs, la valeur est remplacée.

    Cette fonction est utile hors du graphe LangGraph (tests, scripts).
    Dans le graphe, les reducers Annotated jouent le même rôle.

    Args:
        state: État courant (GraphState Pydantic v2).
        updates: Dict partiel de mises à jour.  Les valeurs des champs
            accumulatifs doivent être des listes (ou un seul objet).

    Returns:
        GraphState: Nouvel état après fusion.  L'état d'origine est inchangé
            (immutabilité Pydantic).

    Examples:
        >>> state = GraphState(user_request="test")
        >>> new_state = merge_state_updates(state, {
        ...     "next_agent": "traffic_generator",
        ...     "supervisor_decisions": [
        ...         SupervisorDecision(turn=1, agent_called="topology_designer",
        ...                            reasoning="règle dure", iteration_count=0)
        ...     ],
        ... })
        >>> new_state.next_agent
        'traffic_generator'
        >>> len(new_state.supervisor_decisions)
        1
    """
    # Sérialise l'état courant en dict (les sous-modèles deviennent des dicts)
    current: dict = state.model_dump()

    for key, value in updates.items():
        if key in _ACCUMULATIVE_FIELDS:
            existing: list = current.get(key) or []
            # Accepte une liste ou un seul élément en entrée
            new_items: list = (
                [v.model_dump() if hasattr(v, "model_dump") else v for v in value]
                if isinstance(value, list)
                else [value.model_dump() if hasattr(value, "model_dump") else value]
            )
            current[key] = existing + new_items
        else:
            # Pour les sous-modèles Pydantic scalaires, sérialise en dict
            current[key] = (
                value.model_dump()
                if hasattr(value, "model_dump")
                else value
            )

    return GraphState.model_validate(current)
