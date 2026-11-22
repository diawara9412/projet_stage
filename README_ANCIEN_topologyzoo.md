# Projet Stage — Simulation SDN multi-agents avec LangGraph

## Objectif

Système d'agents LLM (LangGraph) qui orchestrent la simulation d'un réseau SDN :
- Déploiement de topologies réelles du Topology Zoo
- Génération de trafic légitime (HTTP, DNS, transferts)
- Simulation d'attaques (SYN flood, port scan)

## Architecture

4 agents collaborent via le pattern superviseur :
- **Supervisor** : orchestre les workers selon le contexte
- **TopologyDesigner** : sélectionne et déploie une topologie dans Mininet
- **TrafficGenerator** : génère du trafic légitime réaliste
- **AttackSimulator** : injecte des attaques pertinentes selon la topologie

LLM utilisé : **Llama 3.3 70B** via l'API Groq (gratuite).

## Structure du projet

```
projet/
├── scripts/        Scripts standalone des 3 briques
├── topologies/     Fichiers .graphml du Topology Zoo
├── captures/       Captures PCAP du trafic
├── agents/         Code des agents LangGraph
│   ├── supervisor.py
│   ├── topology_designer.py
│   ├── traffic_generator.py
│   └── attack_simulator.py
├── tools/          Outils Python appelés par les agents
│   ├── topology_tools.py
│   ├── traffic_tools.py
│   └── attack_tools.py
├── data/           Données diverses
└── tests/          Tests pytest
```

## Prérequis

- Kali Linux (ou Ubuntu 22+ avec Mininet installé)
- Python 3.10+
- Mininet (réseau SDN simulé)
- Outils Kali : nmap, hping3, wireshark, tcpdump, iperf3
- Clé API Groq (gratuite sur https://console.groq.com)

## Installation

```bash
# 1. Installer les dépendances Python
pip3 install -r requirements.txt --break-system-packages

# 2. Installer Mininet
sudo apt install mininet -y

# 3. Configurer les variables d'environnement
cp .env.example .env
# Éditer .env et renseigner GROQ_API_KEY

# 4. Tester Mininet
sudo mn --test pingall
```

## Utilisation

(à compléter)

## Auteurs

Stage de Master, INRIA RESIST, encadré par M. Badonnel.
