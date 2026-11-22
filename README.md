
# Génération automatique de chaînes de sécurité par agents LLM sur réseau SDN

> **Stage de master — INRIA RESIST / LORIA** (encadrement : Rémi Badonnel).
> Sujet : *Utilisation et comparaison de modèles LLM pour la génération automatique de chaînes de sécurité.*
>
> **Ce document est rédigé comme un rapport détaillé** : il explique le contexte, l'architecture,
> le fonctionnement de chaque composant, l'algorithme, la modélisation mathématique, la méthodologie
> et les résultats de chaque évaluation. Les figures citées sont dans `/home/kali/Desktop/tables/`.



## Table des matières
1. [Contexte et problématique](#1-contexte-et-problématique)
2. [Idée générale et pivot du projet](#2-idée-générale-et-pivot-du-projet)
3. [Architecture : les trois plans](#3-architecture--les-trois-plans)
4. [Le plan intelligent : les agents et LangGraph](#4-le-plan-intelligent--les-agents-et-langgraph)
5. [De l'automate à la chaîne : service, adresse, MaxMind](#5-de-lautomate-à-la-chaîne--service-adresse-maxmind)
6. [Les deux niveaux de contrôle des LLM](#6-les-deux-niveaux-de-contrôle-des-llm)
7. [L'algorithme de génération proactive](#7-lalgorithme-de-génération-proactive)
8. [Le plan de contrôle SDN](#8-le-plan-de-contrôle-sdn)
9. [Le plan de données : pare-feu à états et IDS](#9-le-plan-de-données--pare-feu-à-états-et-ids)
10. [Modélisation mathématique](#10-modélisation-mathématique)
11. [Évaluations : méthodologie et résultats](#11-évaluations--méthodologie-et-résultats)
12. [Technologies utilisées](#12-technologies-utilisées)
13. [Structure du projet](#13-structure-du-projet)
14. [Installation et exécution](#14-installation-et-exécution)

## 1. Contexte et problématique

Une **chaîne de sécurité** (*Security Service Chain*, SFC) est une suite ordonnée de fonctions de
sécurité (pare-feu, IDS/IPS…) qu'un trafic doit traverser. Les configurer manuellement, application
par application, est long et source d'erreurs. L'objectif du stage est de **générer automatiquement**
ces chaînes à l'aide de **modèles de langage (LLM)**, puis de **comparer** plusieurs modèles sur cette
tâche.

**La question de départ posée par l'encadrant :** on ne peut pas partir d'une liste d'adresses
malveillantes pour « fabriquer » une chaîne, car d'où sortirait la notion de « malveillant » ?
La bonne entrée est le **comportement réseau normal** de l'application, décrit par le **laboratoire**
sous forme d'**automate comportemental** (`automates/*.dot`).

**Le modèle retenu est donc la liste blanche (default-deny) :**
- on apprend le **comportement normal** de l'application (les services qu'elle utilise) ;
- on génère une **chaîne en liste blanche** qui autorise ce comportement et **rejette tout le reste** ;
- la **détection** se fait alors par **déviation** : tout ce qui s'écarte du comportement appris est bloqué.

---

## 2. Idée générale et pivot du projet

Le projet a été recentré sur la **phase proactive** : *à partir du comportement normal, générer et
déployer une chaîne de sécurité, puis la tester.* La phase réactive (escalade, boucle autonomique) est
**écartée pour l'instant**.

**Entrée → sortie du système :**

```
Automate comportemental (.dot)      →   agents LLM   →   chaîne de sécurité   →   déploiement SDN   →   test par rejeu
   + traces réseau réelles (.csv)                        (liste blanche)          (règles OpenFlow)      de trafic
```

L'automate décrit **quels services** l'application utilise et **dans quel ordre** (avec des
probabilités). Les traces réelles fournissent **quelles adresses** réalisent chaque service. Les agents
LLM décident **quoi autoriser** et **quoi surveiller**. Le tout est déployé sur un **vrai réseau SDN
émulé** (Mininet + Open vSwitch + contrôleur), puis **testé par rejeu de trafic**.

---

## 3. Architecture : les trois plans

Le système se répartit sur les **trois plans classiques d'une architecture SDN**.
**Figure : `schema_stack_3plans.png`.**

| Plan | Rôle | Composants |
|---|---|---|
| **Plan intelligent (agents)** | DÉCIDE | LangGraph (orchestration + état partagé), LangChain (accès modèles), les modèles LLM (Llama · GPT-OSS · Qwen via l'API Groq), Pydantic (validation des schémas) |
| **Plan de contrôle** | PROGRAMME | os-ken (contrôleur SDN), OpenFlow 1.3 (protocole contrôleur↔commutateurs) |
| **Plan de données (réseau)** | EXÉCUTE | Mininet (émulation), Open vSwitch (commutateurs programmables : **s1** pare-feu, **s2** IDS) |

Le sens de lecture est descendant : le plan intelligent **décide**, le plan de contrôle **programme**,
le plan de données **exécute**. **Seul le plan intelligent contient un modèle de langage.**

---

## 4. Le plan intelligent : les agents et LangGraph

### 4.1 Orchestration par un superviseur (hub-and-spoke)

L'enchaînement des agents est **orchestré par un Superviseur** via **LangGraph** (`StateGraph`).
**Figure : `schema_phase_proactive.png`.**

Principe (topologie en étoile, *hub-and-spoke*) :
- **Aucun agent ne communique directement avec un autre.** Chaque agent lit et écrit un **état partagé**
  (la mémoire fournie par LangGraph) puis **rend la main au Superviseur**.
- Le **Superviseur** consulte l'état, repère le **volet manquant** et **donne l'ordre** à l'agent
  concerné. Il ne fait **aucun travail métier** : il ne fait qu'**aiguiller**.
- Concrètement : chaque agent a une arête `add_edge(agent → superviseur)` ; seul le Superviseur a des
  `add_conditional_edges` qui routent vers le premier volet non produit (`profile is None → analyseur`,
  `firewall_decision is None → firewall`, etc.).

**Déroulé nominal :** `superviseur → analyseur → firewall → ids → vérificateur → déployeur → fin`.
En cas d'incohérence détectée par le Vérificateur, le Superviseur **efface le volet fautif** et
**renvoie l'ordre** à l'agent concerné (reprise ciblée, bornée).

Fichiers de référence : `architectures/supervisor/behavior_supervisor.py` (graphe comportemental),
`architectures/supervisor/graph_supervisor.py` (graphe historique).

### 4.2 Les agents

**Figure : `schema_anatomie_agents.png`.** Deux agents portent un LLM (les seuls qui **jugent**) ;
quatre sont **déterministes** (aucun jugement : lecture, contrôle, exécution, aiguillage).

| Agent | LLM ? | Rôle |
|---|---|---|
| **AgentSuperviseur** | non | consulte l'état partagé, route vers le volet manquant, re-route vers l'agent fautif |
| **AgentAnalyseur** | non | lit l'automate (.dot) + les traces → services, boucles, cadences, enchaînements rares |
| **AgentParefeu** | **oui** | décide pour chaque service : `ALLOW` ou `ALLOW_AND_INSPECT` ; politique par défaut `DENY` |
| **AgentIDS** | **oui** | décide quelles boucles surveiller (signatures de beaconing, seuil = cadence mesurée) |
| **AgentVérificateur** | non | contrôle la chaîne **entière** ; en cas d'erreur, désigne l'agent fautif |
| **AgentDéployeur** | non | assemble la chaîne et l'envoie au contrôleur SDN (REST) → règles OpenFlow |

### 4.3 Anatomie d'un agent porté par un LLM

Un agent LLM (AgentParefeu, AgentIDS) enchaîne : ① un **prompt système** (sa consigne + le format attendu) ;
② le **modèle** (`ChatGroq`) qui produit une décision en **JSON** ; ③ un **contrôle par fonctions
Python** qui compare la sortie au comportement de référence ; ④ une **boucle de correction** qui, en
cas de faute, renvoie un retour ciblé **au même modèle** (jusqu'à 3 fois) ; ⑤ si les 3 tentatives
échouent, un **repli déterministe** produit la chaîne à sa place (aucune génération ne reste bloquée).

**Principe directeur :** un modèle de langage n'intervient **que là où il faut juger**. Lire un
automate, contrôler une cohérence, installer des règles sont des opérations mécaniques, confiées à du
code déterministe pour être **reproductibles et vérifiables**.

---

## 5. De l'automate à la chaîne : service, adresse, MaxMind

C'est le point le plus important à comprendre. **Il y a deux niveaux :**

### 5.1 Le service (ce que le LLM manipule)
Un **service** est un **état de l'automate**, une **étiquette abstraite** de deux natures :
- soit un **port** — `443`, `80`, `4244/4` (viber, lequipe, dropbox, disneyland) ;
- soit une **organisation** — `OVH`, `Amazon`, `Google LLC` (ratp, pokemongo, faceswitch).

Le LLM raisonne **sur ces étiquettes**, jamais sur une adresse. Sa sortie est du type
`{"service": "443", "action": "ALLOW"}`.

### 5.2 L'adresse (ce que le commutateur applique)
Un commutateur ne connaît que des **adresses** et des **ports**. Un module déterministe **traduit**
chaque service en ses **adresses réellement observées dans les traces**, puis produit **une règle
OpenFlow par adresse**. Exemple pour viber : 7 services → ~92 règles de pare-feu + signatures IDS.

### 5.3 La résolution des organisations (MaxMind) et son problème
Pour un service **par port**, la clé (`443`) est **écrite dans les traces** → filtrage direct.
Pour un service **par organisation**, le nom (`OVH`) **n'est pas dans les traces** (qui ne contiennent
que des IP). Il faut un dictionnaire **IP → propriétaire** : c'est le rôle de **MaxMind** (base ASN
**hors-ligne**, déterministe ; RDAP en ligne disponible mais **désactivé par défaut** pour la
reproductibilité). On demande, pour chaque IP des traces, « à qui appartient-elle ? », et on garde
celles dont le propriétaire correspond à l'organisation de l'automate.

**Intérêt de sécurité :** connaître le propriétaire est une **validation** — la chaîne n'autorise pas
n'importe quelle adresse vue, mais seulement celles appartenant aux organisations **prévues**.

**Trois modes d'échec** (tous liés à l'ancienneté des traces, 2015) et leurs correctifs :

| Mode d'échec | Exemple | Correctif appliqué |
|---|---|---|
| IP inconnue de la base (MaxMind renvoie vide) | pokemongo · `173.192.233.73` (vieille plage SoftLayer) | **hybride sûr** : service « (non résolu) » **surveillé** |
| Nom résolu mais non concordant | faceswitch · `85.128.215.22` (« Nazwa.pl » ≠ « NAZWAPL-WEBHOSTING ») | **correspondance de marque assouplie** (préfixe) |
| Organisation = registre, pas hébergeur | pokemongo · « RIPE » | documenté comme limite de l'automate historique |

**Hybride sûr** (`tools/behavior_traces.py`, `enrich(orphan_watch=True)`) : les IP non résolues ne sont
pas perdues ; elles forment un service « (non résolu) » en `ALLOW_AND_INSPECT` (surveillé, **pas**
autorisé à l'aveugle). Le trafic légitime passe (0 % de faux positif), le propriétaire non vérifié est
inspecté, et une déviation vers une autre adresse reste bloquée.

---

## 6. Les deux niveaux de contrôle des LLM

Question de l'encadrant : *« comment sait-on que le LLM s'est trompé ? »* Réponse : par des **fonctions
déterministes** qui comparent la sortie du modèle à une **référence calculée** à partir du comportement.
Une erreur = une **différence d'ensembles**. Il y a **deux niveaux**.

### 6.1 Niveau 1 — les boucles de correction, dans chaque agent
Contrôles appliqués **pendant** la génération, sur la sortie d'**un seul** agent :

| Agent | Vérifie | Opération | Erreur |
|---|---|---|---|
| AgentParefeu | tous les services présents ? | `observés − produits` | **couverture** |
| AgentParefeu | aucun service inventé ? | `produits − comportement` | **invention** |
| AgentParefeu | politique par défaut = DENY ? | comparaison directe | **default-deny** |
| AgentIDS | chaque service surveillé a sa signature ? | `surveillés − signés` | **inspect-sans-signature** |
| les deux | réponse = JSON exploitable ? | analyse syntaxique | **illisible** |

En cas de faute, le message précis est renvoyé au **même modèle**, qui recommence (max 3). Ces
contrôles comparent des **ensembles de noms** ; ils ne jugent **pas** la qualité de la décision.

*Exemples réels capturés :* l'AgentParefeu (llama-3.3-70b) sur dropbox répond `"443/TCP"` au lieu de `"443"` →
`couverture` (443 oublié) + `invention` (443/TCP inventé), corrigé en 1 reprise. qwen3.6-27b répond une
longue réflexion en anglais au lieu de JSON → `illisible` ×6 → repli.

### 6.2 Niveau 2 — l'AgentVérificateur, sur la chaîne entière
Il intervient **après** l'assemblage (`agents/chain_checker.py`, `check_chain`). Il voit ce qu'aucun
agent ne voit seul : la **cohérence globale**. **5 erreurs bloquantes + 4 avertissements :**

- **Erreurs (bloquent le déploiement)** : `coverage`, `invented_service`, `conflict`
  (ALLOW + ALLOW_AND_INSPECT sur un même service), `inspect_without_signature`, `missing_default_deny`.
- **Avertissements (laissent passer, baissent la note)** : `unwatched_rare` (service rare non
  surveillé), `loop_without_threshold`, `not_deployable`, `orphan_signature`.

Note de qualité : `100 − 25 × (erreurs) − 8 × (avertissements)`.

**Erreur vs avertissement :** une erreur rend la chaîne **fausse / non déployable** → renvoi à l'agent.
Un avertissement signale une chaîne **valide mais perfectible** (ex. un rare laissé en `ALLOW` au lieu
de `ALLOW_AND_INSPECT`) → il **ne** repart **pas** aux agents, car (1) c'est un **arbitrage** légitime,
pas une faute objective ; (2) le modèle referait le même choix → boucle inutile ; (3) cela **effacerait
la mesure** de la qualité des modèles ; (4) la chaîne reste **sûre** à déployer.

---

## 7. L'algorithme de génération proactive

**Figure : `schema_algorithme.png` (organigramme).**

```
Entrée : automate comportemental A d'une application, traces réseau T
Sortie : chaîne de sécurité C déployée (règles sur s1, signatures sur s2)

 1  P ← Analyser(A, T)                          ▷ DÉTERMINISTE
 2      services   ← états de A                    (port, plage, ou organisation)
 3      boucles    ← arêtes s→s de A avec leur probabilité
 4      cadence(s) ← intervalle médian intra-session, depuis T
 5      rares      ← { arêtes de A telles que P(arête) < 1 % }
 6      adresses(s)← destinations observées dans T (port : direct ; organisation : via MaxMind)
 7
 8  D ← AgentAvecCorrection(AgentParefeu, P)         ▷ LLM + contrôle
 9      pour chaque service s : D[s] ← ALLOW_AND_INSPECT si s ∈ rares, sinon ALLOW
10      D.défaut ← DENY
11
12  S ← AgentAvecCorrection(AgentIDS, D, boucles)     ▷ LLM + contrôle
13      pour chaque service surveillé : signature de beaconing, seuil ← cadence(s)
14
15  C ← Assembler(D, S, adresses)                ▷ service → règles par adresse
16
17  R ← Vérifier(C, P)                           ▷ AGENT VÉRIFICATEUR
18  si R contient une erreur :
19      le Superviseur efface le volet fautif et renvoie l'ordre à l'agent (max 3 reprises)
20  sinon :
21      Déployer(C) → contrôleur SDN → s1 (pare-feu) et s2 (IDS)
22  retourner C

Fonction AgentAvecCorrection(agent, contexte) :
 a  pour tentative = 1 à 3 :
 b      sortie ← LLM(prompt(agent) + contexte + retour_précédent)
 c      fautes ← Contrôler(sortie)               ▷ couverture · invention · default-deny · signatures
 d      si fautes = ∅ : retourner sortie
 e      retour_précédent ← description des fautes ▷ renvoyée au MÊME LLM
 f  retourner Repli(contexte)                    ▷ chaîne déterministe
```

---

## 8. Le plan de contrôle SDN

- **os-ken** (anciennement Ryu) : le **contrôleur SDN**. Il reçoit la chaîne via une API REST
  (`POST /firewall/install`), la traduit en flux OpenFlow et les installe sur les commutateurs.
  Fichier : `ryu_app/sdn_executor.py`.
- **OpenFlow 1.3** : le protocole par lequel le contrôleur programme les commutateurs Open vSwitch.
- **Mode default-deny** (`--default-deny`) : la règle *table-miss* (priorité 0) est un **DROP**. Seules
  les règles `ALLOW` de la chaîne déployée laissent passer du trafic. **Tout ce qui n'est pas
  explicitement autorisé est rejeté** — c'est le socle de la liste blanche.

**Règles de base indispensables (priorité 50) :** la chaîne inclut 3 règles LAN (ARP, IPv4 local
`10.0.0.0/24`, ICMP local). Sans la règle **ARP**, l'hôte ne résout pas sa passerelle et **aucun trafic
ne circule** — c'est un correctif clé découvert lors des tests live (voir §11.B).

---

## 9. Le plan de données : pare-feu à états et IDS

### 9.1 Topologie
Émulée par **Mininet** : un hôte `h0` (le téléphone, source), un hôte `h1` (puits « Internet »), et
deux commutateurs **Open vSwitch** : **s1** (pare-feu) et **s2** (IDS). Fichier : `deploy_mini_demo.py`.

### 9.2 s1 — le pare-feu À ÉTATS (conntrack)
Le pare-feu sur **s1** utilise le **suivi de connexion (conntrack) natif d'OVS**, en **zone dédiée
(zone 1)**, via un **pipeline à deux tables** :
- **Table 0** : aiguille chaque paquet vers le conntrack — `ct(table=1, zone=1)`.
- **Table 1** : décide selon l'**état** de la connexion :
  - flux **établi** (`+est`) → autorisé (le retour est livré) ;
  - **nouveau** flux vers une destination autorisée → **mémorisé** (`commit`) et autorisé ;
  - **nouveau** flux non sollicité → **rejeté**.

Intérêt : le **trafic de retour** (réponses des serveurs autorisés) est **automatiquement autorisé**
sans règle explicite, tout en gardant le default-deny sur les nouvelles connexions non prévues. La zone
dédiée n'affecte pas le NAT.

### 9.3 s2 — l'IDS
Le commutateur **s2** **duplique** vers le contrôleur le trafic des services placés sous surveillance
(`ALLOW_AND_INSPECT`, priorité 900 → `OUTPUT:CONTROLLER`), pour analyse (domaine, détection de
beaconing par écart à la cadence apprise), puis fait suivre le trafic.

### 9.4 Précision conceptuelle : pare-feu *stateless*, IDS *stateful*
Au-delà de la plomberie conntrack (qui gère le **retour**), il faut distinguer les **rôles** :
- La **décision de sécurité** du pare-feu est un **test statique par paquet** : « (ip, port) est-elle
  dans la liste blanche ? ». Elle est **sans état (*stateless*)** — elle n'a pas besoin de mémoire.
- L'**IDS** détecte des **motifs temporels** (beaconing = communication périodique). Cela exige de
  **mémoriser** les paquets précédents pour mesurer les intervalles. Il est **avec état (*stateful*)**.

Formulation pour le rapport : *« le pare-feu applique une liste blanche sans état (décision par paquet) ;
l'IDS effectue une analyse avec état du comportement temporel (détection de beaconing par écart à la
cadence apprise). »* Le conntrack de s1 reste un détail d'implémentation pour le trafic de retour.

---

## 10. Modélisation mathématique

**① Le comportement = chaîne de Markov.** Sur les services `S = {s₁,…,sₙ}`, matrice de transition
`P = [p_ij]` avec `p_ij = Pr(s_j | s_i)`. Enchaînements rares : `R = {(s_i,s_j) : p_ij < τ}`, `τ = 0,01`.

**② La chaîne = liste blanche.** Chaque service `s` se réalise par des adresses `A(s) ⊆ IP×Port`.
Liste blanche `W = ⋃_s A(s)`. Décision de filtrage :
`D(x) = PASSER si x ∈ W, sinon BLOQUER (default-deny)`.

**③ La détection.** Pour une application de distribution de trafic `𝒟_A` :
`FP = Pr_{x~𝒟_A}(x ∉ W_A)` (trafic légitime bloqué), `TP(B) = Pr_{x~𝒟_B}(x ∉ W_A) = 1 − recouvrement(A,B)`.
Comme `W_A` est construite sur le support de `𝒟_A`, `FP = 0` (couverture complète). Pour une trace
malveillante `ℳ` de support disjoint de `W_A`, le blocage vaut `1`.

**④ Le problème du petit modèle.** La génération est une application `g_θ` de cible la chaîne de
référence `C*`. Le modèle doit produire au niveau des **services** `S`. Ses erreurs :
`couverture = |S \ Ŝ|` (services oubliés), `invention = |Ŝ \ S|` (hors comportement), où `Ŝ` est
l'ensemble produit. Un modèle de faible capacité **ne préserve pas le niveau d'abstraction** : il
énumère les adresses `A(s)` comme des services, d'où `|invention| = |A(s)|`, et une non-convergence
menant au repli. *(Cas réel : disneyland/Llama-3.1-8b, `A(443)` = 5 adresses → 5 inventions → repli.)*

*(Version LaTeX prête à coller disponible dans le rapport — les mêmes équations en `amsmath`.)*

---

## 11. Évaluations : méthodologie et résultats

Deux questions distinctes, deux évaluations séparées : **(A)** quel modèle génère le mieux la chaîne ?
**(B)** la chaîne déployée détecte-t-elle les déviations ? Plus une **(C)** évaluation de robustesse aux
traces malveillantes.

### 11.A — Coût de génération, par modèle
**Objectif :** comparer les modèles sur la génération (temps, appels LLM, tokens).
**Méthode :** `benchmark/eval_behavior_pipeline.py` exécute le pipeline (AgentAnalyseur → AgentParefeu → AgentIDS →
AgentVérificateur) sur **7 applications** × **6 modèles** = **42 exécutions**, et instrumente chaque agent :
appels au modèle, reprises, types d'erreurs, repli, tokens (entrée/sortie), temps, couverture, action.

Modèles évalués : `llama-3.1-8b-instant`, `llama-3.3-70b-versatile`, `gpt-oss-20b`, `gpt-oss-120b`,
`gpt-oss-safeguard-20b`, `qwen3.6-27b`.

**Un « token »** est l'unité de texte lue/écrite par le modèle (~¾ d'un mot) ; c'est l'unité de **coût
et de temps**. La colonne « tokens » = tokens d'entrée (le prompt = le comportement) + tokens de sortie
(la réponse).

**Colonnes des tableaux :** appels AgentParefeu / appels AgentIDS (1 minimum chacun ; une reprise = un appel
supplémentaire, `Reprises = (appels FW − 1) + (appels IDS − 1)`) ; Repli (OUI = le code a produit la
chaîne, résultat à ne pas créditer au modèle) ; Couv. (part des services présents) ; Action (part des
bonnes décisions ALLOW/INSPECT) ; Erreurs (couverture, invention, inspect-sans-signature, illisible).

**Figures : `gen_viber.png`, `gen_lequipe.png`, `gen_dropbox.png`, `gen_disneyland.png`,
`gen_faceswitch.png`, `gen_ratp.png`, `gen_pokemongo.png`** (un tableau par application).

**Résultats clés :**
- Les **boucles de correction** ont détecté et corrigé **113 fautes** sur les 42 exécutions :
  41 illisibles, 39 inventions, 26 oublis (couverture), 6 inspect-sans-signature, 1 erreur réseau.
- **8 chaînes** sont tombées en **repli** : `qwen3.6-27b` sur les 7 apps (il raisonne en anglais au lieu
  de produire du JSON → « illisible ») + `disneyland/llama-3.1-8b` (confond services et adresses IP).
- **Distinction qualité :** une app à **1 service** (dropbox, disneyland) ne **discrimine pas** les
  modèles (aucun jugement, juste un label à recopier) ; les « erreurs » y sont cosmétiques, corrigées
  en 1 reprise. Le vrai discriminant est une app **avec jugement** (viber, 3 enchaînements rares) :
  `action` = 0,57 pour llama-3.1-8b (mauvais), 0,86–1,0 pour les gros modèles. `gpt-oss-120b` produit la
  chaîne de viber **parfaite** (action 1,0) en **un seul appel**.
- **L'AgentVérificateur** n'a trouvé **aucune erreur bloquante** sur les chaînes livrées (les boucles
  d'agent avaient tout réparé), mais a signalé **7 chaînes en avertissement** (`unwatched_rare`) : des
  chaînes valides mais au **jugement imparfait** (bon service, mauvaise action). C'est la **seule** chose
  qu'aucune boucle d'agent ne pouvait voir — la justification de cet agent.

### 11.B — Détection de bout en bout sur le SDN réel
**Objectif :** la chaîne déployée bloque-t-elle les déviations sans bloquer le trafic légitime ?
**Méthode :** `benchmark/e2e_live_matrix.py`. Pour chaque paire (chaîne d'une app A, déviation d'une
app B) : on **construit la chaîne de A**, on la **déploie** sur le SDN (Mininet + OVS + contrôleur en
default-deny, pare-feu à états sur s1), puis on **rejoue** le trafic réel de A (doit passer) et de B
(doit être bloqué) via `benchmark/traffic_test.py`, et on mesure une **matrice de confusion en
pourcentage** (l'arrivée réelle des paquets au puits h1 est mesurée par tcpdump).
*(La chaîne déployée est la chaîne de référence déterministe ; pour un bon modèle comme gpt-oss-120b,
la chaîne générée par le LLM lui est byte-pour-byte identique — vérifié en direct.)*

**Figure : `e2e_pourcentage.png`.**

Deux paires de colonnes : **TN/FP** = trafic légitime de l'app (TN = passé, FP = bloqué à tort) ;
**FN/TP** = trafic de la déviation (TP = bloqué, FN = passé à tort). Comme `TN = 100 − FP` et que
`FP = 0` partout, **TN = 100 % partout** : chaque chaîne laisse passer l'intégralité de son propre
trafic légitime.

| Chaîne | Déviation | FP % | TP % (détection) |
|---|---|---|---|
| viber | dropbox | 0 | 100 |
| viber | lequipe | 0 | 98,7 |
| lequipe | viber | 0 | 97,9 |
| ratp | viber | 0 | 100 |
| dropbox | viber | 0 | 100 |
| pokemongo | viber | 0 | 100 |

**Pourquoi le blocage est à 100 % — et pourquoi pas toujours :** quand les adresses de la déviation sont
**disjointes** de la liste blanche, tout tombe sur le default-deny → 100 % bloqué. Les seuls flux non
bloqués (paires avec lequipe, 97,9–98,7 %) viennent d'un **recouvrement d'adresses** : 2 serveurs
**Akamai** (`2.16.117.168`, `2.16.117.137`) figurent dans les deux listes blanches → recouvrement
inévitable entre applications légitimes, **pas** une faille de détection.

**Deux correctifs déterminants découverts lors des tests live** (invisibles en simulation) :
1. **Deux fichiers de traces désalignés** : la chaîne et le trafic de test lisaient des captures
   différentes de la même app → faux positifs artificiels (viber 22,9 %, lequipe 35,2 %). Corrigé en
   rejouant depuis **la même source** → **FP 0 %**.
2. **Règles ARP/LAN de base absentes** de la chaîne comportementale → sans ARP, **aucun trafic ne
   circulait**. Corrigé en réinjectant les 3 règles LAN (§8).

### 11.C — Robustesse aux traces malveillantes
**Objectif :** créer une trace **proche de viber** (légitime → doit passer) et une trace **modifiée
malveillante** (→ doit être bloquée), déployer viber, tester.
**Méthode :** génération de deux traces synthétiques ; la trace malveillante injecte 4 comportements
d'attaque — **exfiltration** (15 flux), **beaconing C2** (30), **scan de ports** (25), **nouveau
service** IRC (10). Déploiement de viber, rejeu, mesure en direct.

**Figures : `matrice_malveillance.png` (matrice de confusion, 7 métriques), `graphe_attaques_bloquees.png`.**

**Résultat :** trace légitime **100 % acceptée** (29/29, aucun faux positif) ; trace malveillante
**100 % bloquée** (28/28). **Exactitude, précision, rappel, spécificité, F1 = 100 % ; FPR, FNR = 0 %.**
Les 4 types d'attaque sont stoppés **sans avoir été prévus** — c'est la **fermeture par défaut** qui
rejette tout ce qui s'écarte du comportement appris, sans base de signatures de menaces.

---

## 12. Technologies utilisées

| Catégorie | Outil |
|---|---|
| Orchestration d'agents | **LangGraph** (StateGraph, état partagé, routage conditionnel) |
| Accès aux modèles | **LangChain** + **ChatGroq** (API Groq) |
| Modèles LLM | familles **Llama**, **GPT-OSS**, **Qwen** |
| Validation des schémas | **Pydantic** |
| Résolution d'organisations | **MaxMind GeoLite2-ASN** (hors-ligne) ; RDAP (opt-in) |
| Contrôleur SDN | **os-ken** (Ryu), **OpenFlow 1.3** |
| Réseau émulé | **Mininet**, **Open vSwitch** (conntrack) |
| Jeux de données | traces **flowoid** (comportement réel des apps), automates du laboratoire |
| Figures | **matplotlib** · Langage : **Python 3** |

---

## 13. Structure du projet

```
automates/                     automates comportementaux du labo (.dot)
flowoid-traces-intern/         traces réseau réelles (.csv) par application
tools/
  behavior_traces.py           Analyseur : .dot + traces → profil (enrich), résolution org (MaxMind)
  behavior_chain.py            brief(profil) pour les agents ; reference_chain (vérité de référence)
  behavior_deploy.py           to_deployable : service → règles OpenFlow (+ règles LAN de base)
  behavior_profile.py          lecture de l'automate (.dot), notation des ports « 798/3 »
agents/
  chain_checker.py             AgentVérificateur (check_chain) : 5 erreurs + 4 avertissements
architectures/supervisor/
  behavior_supervisor.py       graphe LangGraph du pipeline comportemental (Superviseur + agents)
  firewall_agent.py, ids_agent.py, deployer_agent.py, supervisor_agent.py
ryu_app/sdn_executor.py        contrôleur SDN (os-ken) : default-deny, conntrack, IDS, REST
deploy_mini_demo.py            topologie Mininet (h0, h1, s1 pare-feu, s2 IDS)
benchmark/
  eval_behavior_pipeline.py    évaluation A (coût de génération, 6 modèles × 7 apps)
  e2e_live_matrix.py           évaluation B (détection de bout en bout sur SDN)
  traffic_test.py              rejeu de trafic + mesure d'arrivée réelle (tcpdump)
  make_all_tables.py, make_schemas.py, make_stack_3plans.py   génération des figures
```

---

## 14. Installation et exécution

**Pré-requis :** Python 3, Mininet, Open vSwitch, une clé API Groq dans `.env` (`GROQ_API_KEY`),
la base `enrichment/data/GeoLite2-ASN.mmdb`.

**Générer une chaîne (hors ligne, sans SDN) :**
```bash
python3 -c "from tools.behavior_traces import enrich; from tools.behavior_chain import reference_chain; \
from tools.behavior_deploy import to_deployable, summary; print(summary(to_deployable(reference_chain(enrich('viber')))))"
```

**Déployer et tester sur le SDN (4 terminaux) :**
```bash
# T1 — contrôleur en default-deny
sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --default-deny
# T2 — réseau émulé
sudo python3 deploy_mini_demo.py
# T3 — déployer la chaîne d'une application (REST)
curl -X POST http://127.0.0.1:8080/firewall/install -H "Content-Type: application/json" \
     --data-binary @chain_viber.json
# T4 — rejeu de trafic (légitime doit passer, déviation doit être bloquée)
sudo python3 benchmark/traffic_test.py --profile viber --replay dropbox
```

**Lancer les évaluations :**
```bash
python3 benchmark/eval_behavior_pipeline.py                              # A : coût de génération
sudo python3 benchmark/e2e_live_matrix.py viber:dropbox lequipe:viber    # B : détection e2e
```

---

*Document de référence pour la rédaction du rapport. Toutes les figures sont dans
`/home/kali/Desktop/tables/`. Les chiffres cités sont mesurés (génération : 42 exécutions ;
détection : en direct sur SDN émulé avec pare-feu à états).*

