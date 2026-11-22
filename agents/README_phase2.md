# Agents Phase 2 — Chaînes de sécurité SDN

## Vue d'ensemble

La Phase 2 ajoute un pipeline de 4 agents LangGraph qui transforment l'observation
d'un comportement réseau suspect (automate JSON) en règles OpenFlow déployées sur
les switches OVS du réseau Mininet/SDN.

```
automate JSON
    │
    ▼
┌─────────────────┐
│  ChainAnalyzer  │  Analyse l'automate, détecte les suspects, identifie les légitimes
└────────┬────────┘
         │ AutomateAnalysis
         ▼
┌─────────────────┐
│ ChainGenerator  │  Génère les règles firewall, signatures IDS et actions IPS
└────────┬────────┘
         │ SecurityChain
         ▼
┌─────────────────┐
│ ChainValidator  │  Vérifie la cohérence, corrige les doublons, score 0-100
└────────┬────────┘
         │ SecurityChain (corrigée) + ValidationReport
         ▼
┌─────────────────┐
│ PolicyEnforcer  │  Déploie via REST → sdn_executor.py → os_ken → switches OVS
└────────┬────────┘
         │ DeploymentResult
         ▼
    Flows OpenFlow sur OVS
```

---

## Agent 1 — ChainAnalyzer

**Fichier :** `agents/chain_analyzer.py`
**Outil :** `tools/chain_tools.py::load_automate`

### Input dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `automate_path` | `str` | Chemin vers le fichier `.json` de l'automate |

### Output dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `automate_analysis` | `AutomateAnalysis` | Résultat complet de l'analyse |

### Ce qu'il fait
1. Charge l'automate JSON depuis `automate_path` via `load_automate`
2. Extrait les **transitions suspectes** (score ≥ 4 ou flags présents)
3. Regroupe les **services légitimes** par nom de fournisseur
4. Calcule le **score global** (moyenne pondérée par probabilité)
5. Détermine le `risk_level` : `low` / `medium` / `high` / `critical`
6. Génère des recommandations concrètes pour le ChainGenerator
7. *(LLM)* Produit un `llm_summary` narratif enrichi

### Gardes idempotentes
```python
if state.automate_analysis is not None:
    return {}  # déjà analysé
if not state.automate_path:
    return {}  # rien à faire
```

### Pattern fallback
```
_analyze_deterministic(automate_dict)  →  toujours exécuté, pas de LLM
_enrich_with_llm(analysis)             →  optionnel, si GROQ_API_KEY présente
```

### Modèles Pydantic produits
- `SuspiciousTransition` — transition individuelle avec flags, score, catégorie
- `LegitimateService` — service groupé avec IPs, ports, transition_ids
- `AutomateAnalysis` — tout le résultat de l'analyse

---

## Agent 2 — ChainGenerator

**Fichier :** `agents/chain_generator.py`
**Outil :** `tools/chain_tools.py::generate_chain_from_analysis`

### Input dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `automate_analysis` | `AutomateAnalysis` | Produit par ChainAnalyzer |

### Output dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `security_chain` | `SecurityChain` | Chaîne complète prête à valider |

### Ce qu'il fait
1. Pour chaque `SuspiciousTransition` → crée 1 `FirewallRule` BLOCK (priorité 900)
   - Déduplication par `(ip, port, proto)` : plusieurs transitions → 1 seule règle
2. Pour chaque flag de suspicion → crée 1 `IdsSignature` + 1 `IpsAction` :
   - `tor_exit_node` → `tor_communication` → `DROP_SOURCE` (ou `QUARANTINE` si HIGH)
   - `beaconing` → `beaconing` → `RATE_LIMIT` (5 pps, 300s)
   - `data_exfiltration` → `data_exfiltration` → `DROP_SOURCE`
   - `dga_domain` → `dga_dns` → `ALERT_ONLY`
   - `suspicious_path` → `suspicious_url` → `ALERT_ONLY`
3. Pour chaque `LegitimateService` → crée 1 `FirewallRule` ALLOW (priorité 100)
4. *(LLM)* Enrichit le `generation_summary`

### Gardes idempotentes
```python
if state.automate_analysis is None:
    return {}  # pas d'analyse disponible
if state.security_chain is not None:
    return {}  # déjà généré
```

### Pattern fallback
```
generate_chain_from_analysis(analysis)  →  logique déterministe pure
_enrich_with_llm(analysis, chain)       →  optionnel
```

### Modèles Pydantic produits
- `FirewallRule` — règle FW avec action/priorité/ip/port/protocole
- `IdsSignature` — signature de détection avec match_criteria et sévérité
- `IpsAction` — action automatique liée à une signature (DROP_SOURCE, RATE_LIMIT…)
- `SecurityChain` — les 3 sections + deployment_target + generation_summary

---

## Agent 3 — ChainValidator

**Fichier :** `agents/chain_validator.py`
**Outil :** `tools/chain_tools.py::validate_chain`

### Input dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `security_chain` | `SecurityChain` | Produite par ChainGenerator |

### Output dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `security_chain` | `SecurityChain` | Version corrigée (doublons supprimés) |
| `validation_report` | `ValidationReport` | Rapport complet avec score et issues |

### Ce qu'il fait (6 vérifications)
| # | Catégorie | Sévérité | Description | Correction auto |
|---|-----------|----------|-------------|-----------------|
| 1 | `conflict` | ERROR | BLOCK + ALLOW pour la même IP | Non |
| 2 | `orphan_reference` | ERROR | IpsAction → IdsSignature inexistante | Non |
| 3 | `redundancy` | WARNING | Règles FW identiques `(action, ip, port, proto)` | Oui (suppression) |
| 4 | `priority_issue` | WARNING | ALLOW plus prioritaire que BLOCK sur même IP | Non |
| 5 | `missing_field` | ERROR | `dst_ip` None ou `match_criteria` vide | Non |
| 6 | `best_practice` | WARNING | Pas de QUARANTINE pour HIGH, trop de règles | Non |

**Score qualité :** `100 - 30×ERRORs - 10×WARNINGs` (plancher 0)
**is_valid :** `True` si et seulement si `nb_errors == 0`

### Gardes idempotentes
```python
if state.security_chain is None:
    return {}
if state.validation_report is not None:
    return {}  # déjà validé
```

### Pattern fallback
```
validate_chain(chain)         →  retourne (chain_corrigée, report) — déterministe
_enrich_with_llm(chain, report)  →  optionnel, remplace validation_summary
```

### Modèles Pydantic produits
- `ValidationIssue` — un problème détecté (sévérité, catégorie, règles affectées, suggestion)
- `ValidationReport` — score, is_valid, liste d'issues, stats (doublons supprimés…)

---

## Agent 4 — PolicyEnforcer

**Fichier :** `agents/policy_enforcer.py`
**Outils :** `tools/deployment_tools.py`

### Input dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `security_chain` | `SecurityChain` | Validée par ChainValidator |
| `validation_report` | `ValidationReport` | Doit avoir `is_valid=True` pour déployer |

### Output dans le GraphState
| Champ | Type | Description |
|-------|------|-------------|
| `deployment_result` | `DeploymentResult` | Résultat complet du déploiement |

### Ce qu'il fait
1. `check_firewall_app_alive(endpoint)` — vérifie que l'API REST répond
2. `install_chain_via_rest(chain, endpoint)` — POST /firewall/install
3. Attente de 2s (convergence OpenFlow FLOW_MOD → switches)
4. `fetch_deployment_stats(endpoint)` — GET /firewall/stats (switches connectés, flows)
5. `verify_chain_installed(chain, endpoint)` — GET /firewall/rules (hardware_installed)
6. Détermine `status` : SUCCESS / PARTIAL / FAILED
7. *(LLM)* Enrichit le `deployment_summary`

**Critères de status :**
- **SUCCESS** — `rules_installed == rules_attempted` ET au moins 1 switch connecté
- **PARTIAL** — firewall_app joignable mais 0 switch connecté (règles seront appliquées à la connexion suivante)
- **FAILED** — firewall_app inaccessible, validation invalide, ou erreur HTTP

### Gardes idempotentes
```python
if state.security_chain is None:
    return {}  # rien à déployer
if validation_report.is_valid == False:
    return {"deployment_result": FAILED("déploiement bloqué par validation")}
if state.deployment_result is not None:
    return {}  # déjà déployé
```

### Pattern fallback
```
_deploy_deterministic(chain, endpoint)  →  appels REST + construction DeploymentResult
_enrich_with_llm(result, chain)         →  optionnel, remplace deployment_summary
try/except global → retourne DeploymentResult(status=FAILED, error=str(exc))
```

### Modèles Pydantic produits
- `DeploymentResult` — deployment_id, status, rules_attempted/installed, switches, erreurs

---

## Lancer le pipeline Phase 2

### Prérequis
```bash
# Lancer sdn_executor.py (contrôleur os_ken + REST)
python3 ryu_app/run_manager.py ryu_app.sdn_executor

# Dans un autre terminal, lancer Mininet (pour avoir des switches OVS)
sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
```

### Via les scripts de test individuels
```bash
# Test ChainAnalyzer (analyse pokemon_go.json)
python3 test_chain_analyzer.py automates/pokemon_go.json

# Test ChainGenerator (génère les chaînes depuis les analyses)
python3 test_chain_generator.py

# Test ChainValidator (valide + score qualité)
python3 test_chain_validator.py

# Test PolicyEnforcer (déploie sur sdn_executor.py)
python3 test_policy_enforcer.py
```

### Via Python directement (pipeline complet)
```python
from state import GraphState
from agents.chain_analyzer import chain_analyzer_node
from agents.chain_generator import chain_generator_node
from agents.chain_validator import chain_validator_node
from agents.policy_enforcer import policy_enforcer_node
from state import merge_state_updates

# État initial
state = GraphState(
    user_request="Sécuriser Pokemon GO",
    automate_path="automates/pokemon_go.json",
)

# Pipeline Phase 2
for node_fn in [
    chain_analyzer_node,
    chain_generator_node,
    chain_validator_node,
    policy_enforcer_node,
]:
    updates = node_fn(state)
    if updates:
        state = merge_state_updates(state, updates)

print("Status déploiement :", state.deployment_result.status)
```

---

## Fichiers de sortie (dossier chains/)

| Fichier | Produit par | Description |
|---------|------------|-------------|
| `analysis_*.json` | ChainAnalyzer | AutomateAnalysis sérialisée |
| `chain_*.json` | ChainGenerator | SecurityChain JSON brute |
| `validated_chain_*.json` | ChainValidator | SecurityChain corrigée |
| `validation_*.json` | ChainValidator | ValidationReport JSON |
| `deployment_*.json` | PolicyEnforcer | DeploymentResult JSON |
