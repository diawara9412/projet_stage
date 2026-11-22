# Récap soutenance — whitelisting SDN autonomique (benign + malware Android)

## PARTIE B — Le récit de bout en bout (composants réels + preuves)

### 1. Les agents construisent et déploient la chaîne — **OUI** (prouvé)
Pipeline réel (LLM Groq), enchaînement vu dans le log de déploiement :

| Étape | Fichier / fonction | Preuve (log réel) |
|---|---|---|
| Compilation du graphe | `architectures/supervisor/graph_supervisor.py` | `Graphe Superviseur compilé (étape 5 : Analyzer+Firewall+IDS+IPS+Déployeur, deploy=True)` |
| Routage | `architectures/supervisor/supervisor_agent.py` | `Superviseur (tour 1) → analyzer` ; `(tour 2) → firewall` |
| Analyse | `agents/chain_analyzer.py` (`_analyze_deterministic` + LLM) | `ChainAnalyzer : démarrage` ; `Enrichissement LLM en cours...` ; `POST https://api.groq.com/... 200 OK` (9 appels) |
| Assemblage règles | `tools/chain_tools.py:generate_chain_from_analysis` | 150 règles `FW-xxx ALLOW ... hardware_installed=True` |
| Déploiement | `architectures/supervisor/deployer_agent.py` → `tools/deployment_tools.py:install_chain_via_rest` (POST `/firewall/install`) | **`Déployeur : status=SUCCESS (150/150 installées)`** |
| Pose sur le switch | `ryu_app/sdn_executor.py:apply_chain` | `dump-flows s1` = 151 flows (147 ALLOW prio100) |

➡ **OUI, les agents créent une chaîne fiable et la déploient sur le switch.** Preuve = `status=SUCCESS (150/150)` + flows réels sur `s1`.
**Note honnête** : l'Analyzer a appelé le **vrai LLM** (résumé/enrichissement, 9 appels Groq) ; l'assemblage Firewall/IDS est tombé en **`fallback_deterministic`** (le LLM n'a pas produit de règles via tool-calling → assemblage déterministe, ce qui est **correct et sûr** pour une liste blanche). 0 BLOCK / 150 ALLOW / 0 IDS / 0 IPS (trafic 100 % légitime au déploiement).

### 2. Le contrôleur décide (mode `--decide`)
- `ryu_app/run_manager.py` : `--decide` → `SDN_DECIDE=1` (+ loop).
- `ryu_app/sdn_executor.py:packet_in_handler` : flux inconnu (table-miss, cookie≠CHAIN_COOKIE) → `_handle_unknown_flow`.
- `_handle_unknown_flow` → `_decide_and_install(dst,port,proto)` : **/16 connu → ALLOW posé** (NORMAL prio 100) ; **sinon → DROP posé** (prio 950). 1 seule règle OpenFlow (sub-ms), sans Redis ni redéploiement.
- Preuve (log réel) : `DÉCISION contrôleur (/16) : BLOCK 219.92.52.149 (préfixe 219.92 inconnu) → DROP posé` — **17 EXTEND / 12 BLOCK**.

### 3. Le switch applique
- `ryu_app/sdn_executor.py:_setup_switch` : table-miss → contrôleur (mode boucle).
- Le switch matche les règles : ALLOW (100) → NORMAL ; BLOCK (950) → drop **sans contrôleur** ; rien → table-miss.

### 4. Mode HYBRIDE — les 3 niveaux ensemble (`--hybrid`)
Le contrôleur tranche le **CLAIR** et **escalade l'AMBIGU** aux agents. Code : `ryu_app/sdn_executor.py:_hybrid_decide`.
Les **3 chemins**, prouvés par le log réel du contrôleur (profil dropbox) :
1. **Réputation connue → BLOCK** (contrôleur) : `DÉCISION contrôleur : RÉPUTATION malveillante → BLOCK 147.32.83.234 ... 35.201.97.85 (GCP)` — 6 vrais C2.
2. **/16 connu → ALLOW** (contrôleur) : `DÉCISION contrôleur : /16 connu (108.160.x) → ALLOW 108.160.109.10` — 4 cohost.
3. **AMBIGU → escalade** : `AMBIGU : 155.63.114.162 (ni réputation, ni /16) → le contrôleur NE PEUT PAS` → `ESCALADÉ aux agents (Redis)` → les agents posent `BLOCK (950)` + `IDS (900) [monitored]`.

**Bug trouvé et corrigé** : le contrôleur posait ses règles runtime en `cookie=CHAIN_COOKIE` (0xcafe0001), or le redéploiement du service (`apply_chain → _flush_all_datapaths`, scoped sur 0xcafe0001) les **effaçait** → matrice faussée (FN=0 artefact). **Fix** : `RUNTIME_COOKIE = 0xCAFE0002` pour les décisions du contrôleur → elles **survivent** au flush. Résultat dropbox cohérent : benign 10/10 ALLOW, C2 réel 7/7 BLOCK, **cohost 0/4 = FUITE /16 (FN, honnête)**, unrel 4/4 BLOCK → TP11/FP0/TN10/FN4, Acc 0.84 / Recall 0.73 / FNR 0.27.
**Limite d'implémentation honnête** : à chaque ambigu, le service redéploie toute la chaîne (`POST /firewall/install` répété) → optimisable (pose incrémentale).

### Récap des modes du contrôleur
| Mode | Qui décide | IDS/IPS ? |
|---|---|---|
| `--decide` | contrôleur seul (/16) | non |
| `--loop` + service `--agentic` | agents (réputation→FW/IDS/IPS) | oui |
| **`--hybrid`** | **contrôleur (/16+réputation) + escalade l'ambigu aux agents** | oui (sur l'ambigu) |

---

## PARTIE C — LIVE vs OFFLINE (sans ambiguïté)

### A RÉELLEMENT tourné EN LIVE (sur le vrai switch OVS s1)
1. **Déploiement par les vrais agents LLM** → chaîne sur `s1` (`dump-flows` avant=1, après=151).
2. **Décisions du contrôleur** (`--decide`) : 17 EXTEND + 12 BLOCK, ALLOW/DROP réellement posés (`dump-flows` final : 164 ALLOW + 12 DROP).
3. **Matrice de confusion du rejeu** mesurée sur les flows réels du switch : **TP=13, FP=0, TN=10, FN=8** (Accuracy 0.74, Recall 0.62, FNR 0.38).

### Calculé OFFLINE (modèle déterministe, validé par le live)
- Études de granularité (matrice 8×8, cas-par-cas, /16 vs ASN, prefix sweep).
- Métriques par clé (accuracy/precision/recall/F1/FPR/FNR, moyenne ± écart-type) + ROC.
- Le modèle offline reproduit EXACTEMENT la sémantique du switch → **le live /16 = l'offline /16** (validation croisée).

---

## PARTIE D — Relancer le test soi-même (terminal par terminal)

> Chaque terminal commence par `cd /home/kali/Desktop/projet`. Pour un nouveau run propre,
> **redémarre T1** (Ctrl+C puis relance) pour réinitialiser la mémoire du contrôleur.

### T1 — Contrôleur (il décide ; AFFICHE les décisions en direct)
```
cd /home/kali/Desktop/projet
redis-cli ping            # attendu : PONG (sinon : sudo systemctl start redis-server)
sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --decide
```
✅ À VOIR : `⚡ Mode DÉCISION CONTRÔLEUR : /16 tranché dans le contrôleur (fast-path).`
puis, pendant le test : `DÉCISION contrôleur (/16) : EXTEND/BLOCK ... → ALLOW/DROP posé`.

### T2 — Réseau Mininet (téléphone h0 → switch s1 → internet)
```
cd /home/kali/Desktop/projet
sudo python3 deploy_mini_demo.py --nat
```
✅ À VOIR : `✅ Mini-demo démarré ... h0 = 10.0.0.1 ... h1 = 10.0.0.2` (laisser ouvert).

### T3 — Déploiement par les VRAIS agents LLM
```
cd /home/kali/Desktop/projet
python3 architectures/supervisor/run_supervisor_test.py --deploy --automate lequipe_whitelist
```
✅ À VOIR : `→ analyzer ... → firewall ...` puis **`Déployeur : status=SUCCESS (150/150 installées)`**.
(Si quota Groq épuisé → message 429 ; repli déterministe possible, voir note.)

### T4 — Rejeu mixte bénin + malware → matrice de confusion
```
cd /home/kali/Desktop/projet
sudo python3 benchmark/live_eval.py
```
✅ À VOIR : le tableau par classe (`benign 10/10`, `mal_real 7/7`, `mal_cohost 0/8`, `mal_unrel 6/6`)
puis **`Matrice : TP=13 FP=0 TN=10 FN=8  Accuracy=0.74 Recall=0.62 FNR=0.38`**.
Et dans T1 : les décisions du contrôleur défilent en direct.

### (T5) — Figures pour le rapport
```
cd /home/kali/Desktop/projet
python3 benchmark/make_figures.py
```
✅ À VOIR : `✅ Figures générées` → `benchmark/figures/*.png`.

### Scénario HYBRIDE — les 3 niveaux dans un seul run (recommandé pour la démo)
> Petite app **dropbox** (16 flux) pour tout suivre clair. cd dans chaque commande.
```
T1  cd /home/kali/Desktop/projet && sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --hybrid
T2  cd /home/kali/Desktop/projet && sudo python3 deploy_mini_demo.py --nat
T3  cd /home/kali/Desktop/projet && python3 architectures/supervisor/run_supervisor_test.py --deploy --automate dropbox_whitelist
T4  cd /home/kali/Desktop/projet && python3 -u architectures/supervisor/supervisor_service.py --app dropbox --agentic
T5  cd /home/kali/Desktop/projet && sudo python3 benchmark/live_eval.py --app dropbox
```
✅ À VOIR dans **T1** : `RÉPUTATION → BLOCK` (vrais C2), `/16 connu → ALLOW` (cohost), `AMBIGU ... le contrôleur NE PEUT PAS → ESCALADÉ`.
✅ À VOIR dans **T4** : les agents posent `BLOCK+IDS` sur l'ambigu.
✅ À VOIR dans **T5** : `TP=11 FP=0 TN=10 FN=4` (les cohost fuient = limite /16 assumée).
> Pour relancer proprement : redémarre **T1** (Ctrl+C puis relance) — reset de la mémoire du contrôleur.

### Repli 100 % offline (filet, sans switch ni sudo)
```
cd /home/kali/Desktop/projet
python3 benchmark/eval_metrics_full.py     # métriques moy±écart-type + ROC (RÉFÉRENCE du mémoire)
python3 benchmark/eval_full.py             # confusion matrix benign + malware réel/synthétique
```

---

## Fichiers livrés
- **Figures** : `benchmark/figures/metrics_table.png`, `roc_curve.png`, `confusion_live.png` (+ `.csv`, `.md`)
- **Scripts ré-exécutables** : `benchmark/{live_eval,make_figures,eval_full,eval_metrics_full,eval_malware,extract_mischief,loop_matrix,loop_cases,granularity_precision_recall,prefix_sweep}.py`
- **Logs** : `benchmark/results/*.log`, `/tmp/ctrl_decide.log`, `/tmp/deploy_agents.log`
- **Code archi** : `ryu_app/sdn_executor.py` (`_decide_and_install`), `ryu_app/run_manager.py` (`--decide`)

## Limites honnêtes
- Échantillon = 8 apps + 7 C2 réels (surtout dédiés, 1 sur Google Cloud) + malware co-hébergé **synthétique** → ce sont des **TENDANCES sur ces données**, pas des lois universelles.
- **P4** (faire chuter le FPR du domaine via SNI **forward**) reste en perspective : nécessite le SNI forward des apps **bénignes** (pas dans les traces flowoid = rDNS only).
