# Démo Phase 2 — Pipeline de sécurité SDN complet

## Vue d'ensemble

La Phase 2 transforme automatiquement l'observation d'un comportement réseau
(automate JSON) en règles OpenFlow déployées sur les switches OVS d'Abilene.

```
automate JSON  →  [ChainAnalyzer]  →  AutomateAnalysis
               →  [ChainGenerator] →  SecurityChain (firewall + IDS + IPS)
               →  [ChainValidator] →  Chaîne validée + rapport qualité
               →  [PolicyEnforcer] →  Déploiement sur OVS via os-ken REST
```

---

## Prérequis

| Composant      | Version  | Statut   |
|----------------|----------|----------|
| Python         | 3.13.12  | ✅ installé |
| os-ken         | 4.2.0    | ✅ installé |
| Open vSwitch   | 3.7.1    | ✅ installé |
| Mininet        | 2.3.1b4  | ✅ installé |
| GROQ_API_KEY   | —        | ✅ dans .env |

---

## Démo allégée (recommandée pour VM modeste)

Topologie minimale : **2 hosts + 1 switch** au lieu des 11 nœuds d'Abilene.
Idéal pour les VMs avec peu de RAM (< 4 Go) ou processeur limité.

### Terminal 1 — Contrôleur os-ken

```bash
python3 ryu_app/run_manager.py ryu_app.sdn_executor
```

Attendre :
```
INFO ryu_app.sdn_executor: SdnExecutor initialisée — REST sur port 8080
INFO ryu_app.sdn_executor: Serveur REST démarré sur http://0.0.0.0:8080
```

### Terminal 2 — Mininet minimal (2 hosts + 1 switch)

```bash
sudo python3 deploy_mini_demo.py
```

### Terminal 3 — Pipeline Phase 2

```bash
python3 main_phase2.py --automate automates/pokemon_go.json
```

### Tests dans le CLI Mininet (Terminal 2)

```
mininet> h0 ping -c 3 h1
```
→ **0% packet loss** — FW-003 (ALLOW ICMP 10.0.0.0/24, priorité 50) laisse passer

```
mininet> sh ovs-ofctl dump-flows s1 -O OpenFlow13
```
→ **11 règles OpenFlow** installées par os-ken :
```
cookie=0xcafe0001, priority=50,  arp                       actions=NORMAL   ← FW-002
cookie=0xcafe0001, priority=50,  ip,nw_dst=10.0.0.0/8     actions=NORMAL   ← FW-001
cookie=0xcafe0001, priority=50,  icmp,nw_dst=10.0.0.0/8   actions=NORMAL   ← FW-003
cookie=0xcafe0001, priority=900, ip,nw_dst=185.220.101.47  actions=drop     ← BLOCK Tor
cookie=0xcafe0001, priority=900, ip,nw_dst=91.108.4.201    actions=drop     ← BLOCK C2
cookie=0xcafe0001, priority=100, ip,nw_dst=35.186.224.10   actions=NORMAL   ← ALLOW Niantic
...
```

---

## Démo 1 — Analyse seule (sans réseau, sans sudo)

Le mode le plus simple : analyser un automate et générer une chaîne sans déploiement.

```bash
# Depuis la racine du projet
python3 main_phase2.py --automate automates/malware_app.json --skip-deploy
```

**Sortie attendue :**
```
📊 ANALYSE
   Application         : FlashLight Pro (compromised)
   Score suspicion     : 7.01 / 10
   Niveau de risque    : HIGH
   Transitions         : 7 total (5 suspectes, 2 services légitimes)

🛡️  CHAÎNE GÉNÉRÉE
   Règles firewall     : 4 (2 BLOCK, 2 ALLOW)
   Signatures IDS      : 5
   Actions IPS         : 5   (dont 1 QUARANTINE)

✅ VALIDATION
   Score qualité       : 90 / 100
   is_valid            : True

🚀 DÉPLOIEMENT
   (déploiement sauté — mode dry-run)
```

Tester sur les 3 automates disponibles :
```bash
python3 main_phase2.py --automate automates/pokemon_go.json  --skip-deploy
python3 main_phase2.py --automate automates/banking_app.json --skip-deploy
python3 main_phase2.py --automate automates/malware_app.json --skip-deploy
```

---

## Démo 2 — Pipeline complet avec contrôleur (sans Mininet)

Déployer une chaîne sur sdn_executor.py, sans switch OVS réel.
firewall_app accepte la chaîne et l'appliquera aux switches dès leur connexion.

### Terminal 1 : lancer le contrôleur os-ken
```bash
python3 ryu_app/run_manager.py ryu_app.sdn_executor
```

Attendre d'avoir :
```
INFO ryu_app.sdn_executor: SdnExecutor initialisée — REST sur port 8080
INFO ryu_app.sdn_executor: Serveur REST démarré sur http://0.0.0.0:8080
```

### Terminal 2 : lancer le pipeline
```bash
python3 main_phase2.py --automate automates/pokemon_go.json
```

**Résultat attendu :** `Status: ⚠ PARTIAL` (pas de switch OVS connecté pour l'instant).

Vérifier que la chaîne est bien enregistrée :
```bash
curl -s http://127.0.0.1:8080/firewall/stats | python3 -m json.tool
curl -s http://127.0.0.1:8080/firewall/rules | python3 -m json.tool
```

---

## Démo 3 — Pipeline complet avec Mininet + Abilene (démo complète)

### Étape 1 : lancer le contrôleur os-ken (Terminal 1)

```bash
python3 ryu_app/run_manager.py ryu_app.sdn_executor
```

### Étape 2 : déployer une chaîne de sécurité (Terminal 2)

```bash
# Choisir le scénario le plus démonstratif (malware HIGH risk)
python3 main_phase2.py --automate automates/malware_app.json
```

Vérifier : `Status: ⚠ PARTIAL` (switches pas encore connectés).

### Étape 3 : connecter Abilene au contrôleur (Terminal 3, sudo requis)

```bash
sudo python3 deploy_abilene_with_controller.py
```

**Ce qui se passe :**
1. Les 11 switches OVS s'enregistrent auprès de sdn_executor.py (port 6653)
2. firewall_app installe immédiatement la chaîne active sur chaque switch
3. Les flows OpenFlow apparaissent sur les switches

Vérifier dans le terminal os-ken (Terminal 1) :
```
INFO ryu_app.sdn_executor: Switch 000000000000000X connecté — règle table-miss installée
INFO ryu_app.sdn_executor: Switch 000000000000000X : ré-application de la chaîne 'chain_malware_app_v1'
INFO ryu_app.sdn_executor:   BLOCK → DROP : FW-001  198.98.54.218:8080/HTTP
INFO ryu_app.sdn_executor:   BLOCK → DROP : FW-002  185.220.100.252:9001/TCP
INFO ryu_app.sdn_executor:   IDS → CLONE+FWD : IDS-003 [tor_communication]  185.220.100.252:9001
```

### Étape 4 : inspecter les flows depuis Mininet CLI

Dans le terminal Mininet (Terminal 3) :
```
mininet> s0 ovs-ofctl -O OpenFlow13 dump-flows s0
```

Vous devez voir :
```
cookie=0xcafe0001, priority=900, ip,nw_dst=198.98.54.218 actions=drop
cookie=0xcafe0001, priority=900, ip,nw_dst=185.220.100.252 actions=drop
cookie=0xcafe0001, priority=950, ip,nw_dst=185.220.100.252 actions=CONTROLLER,NORMAL
cookie=0xcafe0001, priority=100, ip,nw_dst=104.21.45.12 actions=NORMAL
```

### Étape 5 : simuler du trafic et observer les alertes IDS

Depuis Mininet CLI :
```
# Trafic légitime (vers Cloudflare 104.21.45.12) → doit passer (ALLOW)
mininet> h0 curl -s --connect-timeout 2 https://104.21.45.12 || echo "timeout attendu"

# Trafic suspect (vers C2) → doit être DROP
mininet> h0 ping -c 2 -W 1 198.98.54.218 || echo "DROP confirmé"
mininet> h0 ping -c 2 -W 1 185.220.100.252 || echo "DROP confirmé"
```

Consulter les alertes IDS depuis Terminal 2 :
```bash
curl -s http://127.0.0.1:8080/firewall/stats | python3 -c "
import json, sys
d = json.load(sys.stdin)
for sid, info in d['ids_alerts'].items():
    print(f'{sid}: {info[\"pattern_type\"]} → {info[\"count\"]} alertes')
"
```

### Étape 6 : changer de chaîne à chaud

Sans redémarrer os-ken ni Mininet, pousser une nouvelle chaîne :
```bash
# Depuis Terminal 2 : changer pour la chaîne Pokemon GO
curl -s -X POST http://127.0.0.1:8080/firewall/install \
     -H "Content-Type: application/json" \
     -d @chains/chain_pokemon_go.json | python3 -m json.tool
```

Les flows précédents sont supprimés (via OFPFC_DELETE cookie=0xCAFE0001)
et les nouveaux sont installés immédiatement sur tous les switches connectés.

### Étape 7 : nettoyage

```
mininet> exit         # Termine Mininet (Terminal 3)
Ctrl+C               # Arrête os-ken (Terminal 1)
```

---

## Référence des commandes

### Pipeline principal
```bash
# Dry-run (analyse + génération + validation uniquement)
python3 main_phase2.py --automate <fichier> --skip-deploy

# Pipeline complet avec déploiement
python3 main_phase2.py --automate <fichier>

# Avec endpoint personnalisé (os-ken sur une autre machine)
python3 main_phase2.py --automate <fichier> --endpoint http://10.0.0.1:8080/firewall
```

### Contrôleur os-ken
```bash
# Lancer (reste en premier plan)
python3 ryu_app/run_manager.py ryu_app.sdn_executor

# Vérifier qu'il tourne
ss -tlnp | grep -E '6653|8080'
```

### API REST firewall_app
```bash
# Santé
curl http://127.0.0.1:8080/

# Statistiques
curl http://127.0.0.1:8080/firewall/stats

# Règles installées
curl http://127.0.0.1:8080/firewall/rules

# Installer une chaîne
curl -X POST http://127.0.0.1:8080/firewall/install \
     -H "Content-Type: application/json" \
     -d @chains/chain_malware_app.json

# Supprimer toutes les règles
curl -X DELETE http://127.0.0.1:8080/firewall/flush
```

### Topologie Abilene avec contrôleur
```bash
# Lancer Abilene connectée à os-ken (requiert sudo + os-ken déjà lancé)
sudo python3 deploy_abilene_with_controller.py

# Lancer Abilene standalone (pour tests sans contrôleur)
sudo python3 deploy_abilene.py
```

### Scripts de test individuels
```bash
python3 test_chain_analyzer.py automates/malware_app.json
python3 test_chain_generator.py
python3 test_chain_validator.py
python3 test_policy_enforcer.py   # nécessite firewall_app lancé
```

---

## Fichiers produits

Tous les artefacts intermédiaires sont sauvegardés dans `chains/` :

| Fichier | Produit par | Description |
|---------|------------|-------------|
| `analysis_*.json` | test_chain_analyzer | AutomateAnalysis |
| `chain_*.json` | test_chain_generator | SecurityChain brute |
| `validated_chain_*.json` | test_chain_validator | SecurityChain corrigée |
| `validation_*.json` | test_chain_validator | ValidationReport |
| `deployment_*.json` | test_policy_enforcer | DeploymentResult |
| `pipeline_result_*.json` | main_phase2.py | État complet Phase 2 |

---

## Dépannage

### os-ken ne démarre pas
```bash
# Vérifier l'installation
python3 -c "import os_ken; print(os_ken.__version__)"

# Réinstaller si nécessaire
pip3 install os-ken --break-system-packages
```

### Port 6653 déjà occupé
```bash
# Trouver le processus
ss -tlnp | grep 6653
# Ou
fuser 6653/tcp

# Tuer le processus os-ken précédent
pkill -f run_manager
```

### Aucun switch ne se connecte à os-ken
```bash
# Vérifier qu'OVS tourne
sudo systemctl status openvswitch-switch

# Vérifier que les switches pointent vers le bon contrôleur
sudo ovs-vsctl show | grep controller
```

### API REST inaccessible
```bash
# Port 8080 ouvert ?
ss -tlnp | grep 8080

# Firewall local ?
sudo iptables -L | grep 8080

# Test direct
curl -v http://127.0.0.1:8080/
```

### Pipeline trop lent (appels LLM)
Les enrichissements LLM (Groq API) peuvent prendre 2-5 secondes par agent.
Sans clé API, le pipeline fonctionne en mode 100% déterministe (plus rapide).
Pour désactiver les appels LLM : retirer GROQ_API_KEY du fichier `.env`.
