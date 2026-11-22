# DÉMO SOUTENANCE — génération + déploiement d'une chaîne de sécurité

> Objectif : montrer en **direct** que la chaîne de viber, générée à partir du comportement
> normal, **laisse passer** le trafic légitime et **bloque** une déviation/attaque —
> preuve visuelle avec **Wireshark** + compteurs OpenFlow.
>
> `cd /home/kali/Desktop/projet_chaine` avant tout. Mot de passe sudo : `kali`.

---

## 0. Préparation (une fois, AVANT la soutenance)

**a) Générer la chaîne de viber en JSON** (pour le déploiement REST) :
```bash
python3 -c "
import json
from tools.behavior_traces import enrich
from tools.behavior_chain import reference_chain
from tools.behavior_deploy import to_deployable
json.dump(to_deployable(reference_chain(enrich('viber'))), open('chain_viber.json','w'))
print('chain_viber.json OK')
"
```

**b) Vérifier que les ports SDN sont libres** (sinon T1 plante) — tuer par PID, jamais par motif :
```bash
ss -ltnp | grep -E ':8080|:6653'      # si occupé → sudo kill <pid affiché>
```

**c) RÉPÉTER toute la démo au moins 2 fois la veille.** (voir §6 si un mode pose problème)

---

## 1. Les 4 terminaux (dans l'ordre)

### T1 — Contrôleur SDN (fermeture par défaut, pare-feu à états, 2 switches)
```bash
sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor \
     --default-deny --two-switch --sfc --stateful
```
> Attends la ligne « DEFAULT-DENY (liste blanche) ». Laisse tourner.
> **À dire :** « Le contrôleur démarre en *default-deny* : tout ce qui n'est pas
> explicitement autorisé sera rejeté. s1 = pare-feu à états, s2 = IDS. »

### T2 — Réseau émulé (h0 → s1 pare-feu → s2 IDS → h1)
```bash
sudo python3 deploy_mini_demo.py --two-switch
```
> Tu obtiens le prompt `mininet>`. **À dire :** « h0 = l'appareil surveillé,
> h1 = le puits (Internet), et entre les deux la chaîne s1 puis s2. »

### T3 — Déployer la chaîne de viber
```bash
curl -X POST http://127.0.0.1:8080/firewall/install \
     -H "Content-Type: application/json" --data-binary @chain_viber.json
```
Puis **montre les règles installées** (effet « waouh ») :
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | head -30
```
> **À dire :** « Une politique abstraite (états ALLOW/INSPECT) vient de devenir
> 92 règles OpenFlow concrètes sur le pare-feu, plus la règle de rejet par défaut. »

### T4 — Rejeu du trafic (mesure automatique passe/bloqué)
```bash
sudo python3 benchmark/traffic_test.py --profile viber --replay dropbox
```
> Le script rejoue le trafic **de viber** (doit PASSER) puis celui de **dropbox**
> (déviation, doit être BLOQUÉ) et mesure l'arrivée réelle sur h1.
> **À dire :** « viber traverse à 100 %, dropbox tombe sur le default-deny. »

---

## 2. Wireshark — la preuve visuelle

Les interfaces des switches sont visibles dans ton bureau normal (namespace root).

1. Ouvre Wireshark en root : `sudo wireshark`
2. **Vérifie les noms d'interfaces** (dans un terminal ou `mininet> links`) :
   ```bash
   ip -br link | grep -E 's1-eth|s2-eth'
   ```
   En principe (topo `--two-switch`) :
   - **`s1-eth1`** = ce que **h0 envoie** (tout le trafic émis) ;
   - **`s1-eth2`** = ce qui **arrive au puits h1** (donc ce qui a été autorisé).
3. Lance la capture sur **`s1-eth1` ET `s1-eth2`**.
4. Filtre d'affichage : `ip && !arp`

**Lecture :**
- **Trafic viber (légitime)** → paquets visibles sur `s1-eth1` **et** `s1-eth2` → ils traversent. ✅
- **Trafic dropbox (déviation)** → visibles sur `s1-eth1` mais **PAS** sur `s1-eth2` → **droppés**. 🚫

---

## 3. La preuve chiffrée (compteurs OpenFlow)

Pendant/après le test, montre que la règle de **rejet** encaisse les paquets bloqués :
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E "priority=0|drop"
```
> Le champ `n_packets` de la règle **drop** (table-miss) **grimpe** avec dropbox,
> et ne bouge pas avec viber. C'est le default-deny en action.

**Bonus pare-feu à états** (si tu veux impressionner) :
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -i "ct"
```
> **À dire :** « Grâce au suivi de connexion (conntrack), le trafic de **retour**
> des serveurs légitimes est autorisé **sans aucune règle** qui le mentionne, alors
> qu'une connexion entrante non sollicitée reste bloquée. »

---

## 4. Ordre de présentation conseillé (≈ 4 min)

1. T1 + T2 lancés → « voici le réseau et le contrôleur en default-deny ».
2. T3 → déploiement → `dump-flows` : « la politique devient des règles ».
3. Wireshark prêt (s1-eth1 / s1-eth2).
4. **Test 1** viber → Wireshark : ça passe. ✅
5. **Test 2** dropbox → Wireshark : ça disparaît. 🚫 + `dump-flows` drop counter.
6. Conclusion : matrice de confusion (29 légitimes / 80 malveillants, 100 %).

---

## 5. Deuxième démo (facultative) — robustesse à une attaque

Rejoue la trace malveillante synthétique contre la chaîne de viber :
```bash
sudo python3 benchmark/traffic_test.py --profile viber --replay dropbox
# (ou la trace d'attaque dédiée si disponible : --replay synthetique_malveillant)
```
> **À dire honnêtement :** « Ces adresses/ports sont hors liste blanche → 100 %
> attendu. Ça valide le default-deny, pas une détection générale : une attaque sur
> une adresse déjà autorisée relèverait de l'inspection s2 (perspective). »

---

## 6. Dépannage (à connaître)

| Symptôme | Cause / solution |
|---|---|
| Rien ne passe, même viber | Règles ARP/LAN manquantes → normalement corrigé (`_lan_base_rules`). Vérifie `mininet> h0 ping h1`. |
| T1 refuse de démarrer | Port 6653/8080 occupé → `ss -ltnp | grep -E ':8080|:6653'` puis `sudo kill <pid>`. |
| Le mode stateful/2-switch bug | **Repli sûr** : relance T1 en `--default-deny` seul et T2 sans `--two-switch`. Le blocage default-deny (le résultat clé) marche pareil. |
| Wireshark ne voit pas s1-ethX | Lance-le **après** T2 (les interfaces n'existent qu'une fois Mininet démarré) ; `sudo wireshark`. |
| Quitter proprement | `mininet> exit` (T2), puis Ctrl-C sur T1. Si un process traîne : tuer par **PID/port**, pas par motif. |

## 7. Filet de sécurité (OBLIGATOIRE)

- Enregistre une **capture .pcap** de chaque test (Wireshark → Fichier → Enregistrer).
- Fais une **courte vidéo** de la démo qui marche.
- Si le live plante devant le jury → tu montres l'enregistrement, zéro stress.

---

**Rappel des vrais chiffres (viber) :** 7 états · 3 transitions rares · 5 états surveillés ·
**92 règles pare-feu (+3 LAN)** · **80 signatures s2** · Vérificateur **100/100** ·
détection : viber bloque dropbox **100 %**, faux positifs **0 %**.
