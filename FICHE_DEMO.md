# Fiche démo — projet_chaine (3 étapes + hybride + politique IDS)

> Chaque terminal commence par `cd /home/kali/Desktop/projet_chaine`.
> Mot de passe sudo = `kali`. Pour un run propre, redémarre T1 (Ctrl+C puis relance).

## Les flags du contrôleur (à composer selon ce qu'on veut montrer)
| Flag | Rôle |
|---|---|
| `--hybrid` | 3 niveaux : réputation→BLOCK, /16→ALLOW, ambigu→agents (Redis) |
| `--sfc` | 2 switches (s1=FW, s2=IDS) + chaînage explicite (implique 2 switches) |
| `--stateful` | conntrack natif (allow-then-inspect, pare-feu à états) |
| `--inspect` | l'IDS surveille le trafic AUTORISÉ + escalade→BLOCK si détection fine |

**Commande complète (tout activé) :**
```
sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --hybrid --sfc --stateful --inspect
```

---

## ⭐ TEST COMPLET EN 1 COMMANDE

```
cd /home/kali/Desktop/projet_chaine
bash test_complet.sh
```
Enchaîne tout automatiquement (~4-5 min) et affiche le résultat de chaque phase :
1. **Contrôleur + réseau** (FW s1 + IDS s2 + réputation/16 + agents + SNI + beaconing).
2. **Déploiement** : les agents déploient la whitelist → le contrôleur **répartit** (règles firewall→s1, signatures IDS→s2).
3. **Rejeu du dataset Mischief** → matrice `TP=11 FP=0 TN=10 FN=4` + **qui attrape quoi** (réputation / /16 / agents).
4. **SNI** : IP de confiance + domaine C2 → **s2 attrape le domaine** → BLOCK s1.
5. **Beaconing** : rappels réguliers → **s2 attrape le comportement** → BLOCK s1.

Génère 2 pcaps pour **Wireshark** : `~/Desktop/test_cote_h0.pcap` et `~/Desktop/test_cote_IDS.pcap`.
Puis nettoie tout seul. (Prérequis : `echo 'echo kali' > ~/.askpass.sh && chmod +x ~/.askpass.sh`.)

---

## SCÉNARIO A — Le pipeline complet + la mesure (le principal)

```
T1  cd /home/kali/Desktop/projet_chaine
    sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --hybrid --sfc --stateful --inspect

T2  cd /home/kali/Desktop/projet_chaine
    sudo python3 deploy_mini_demo.py --two-switch --nat        # → prompt mininet>  (laisser ouvert)

T3  cd /home/kali/Desktop/projet_chaine
    python3 architectures/supervisor/run_supervisor_test.py --deploy --automate dropbox_whitelist

T4  cd /home/kali/Desktop/projet_chaine
    python3 -u architectures/supervisor/supervisor_service.py --app dropbox --agentic

T5  cd /home/kali/Desktop/projet_chaine
    sudo python3 benchmark/live_eval.py --app dropbox
```

**À voir :**
- **T3** : `→ analyzer → firewall (source=llm) → SUCCESS 19/19` (tes agents déploient).
- **T1** : `ALLOW → conntrack` (stateful) ; `RÉPUTATION → BLOCK` (C2) ; `/16 connu → ALLOW` (cohost) ; `AMBIGU → escaladé`.
- **T4** : `[BLOCK] ...` (les agents tranchent l'ambigu — BLOCK seul, plus de IDS redondant).
- **T5** : `TP=11 FP=0 TN=10 FN=4  Accuracy=0.84`.

Vérifs (dans T2, `mininet>`) :
```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 'ct(table=1'    # ALLOW stateful (aller→ct)
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=1                # +new/+est/+drop
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s2 | grep priority=900    # IDS surveille l'autorisé
```

---

## SCÉNARIO B — Étape 3 : l'IDS rattrape (defense in depth, signal = réputation)

Principe : le firewall peut AUTORISER une IP (whitelist/​/16) qui est en fait un C2
connu de la réputation. L'IDS re-vérifie la réputation du trafic autorisé et la
BLOQUE. **Aucun fichier à remplir** — le signal vient de `threat_intel` (mischief_c2).

Monter T1 (contrôleur `--hybrid --sfc --stateful --inspect`) + T2 (réseau). Puis on
déploie une chaîne qui « fait confiance » à un vrai C2 (35.201.97.85) — depuis un 3e term :
```
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"chain_id":"dd","source_app_name":"dd","global_risk_level":"low",
       "firewall_rules":[{"id":"T","action":"ALLOW_AND_INSPECT","dst_ip":"35.201.97.85","protocol":"TCP","dst_port":443,"priority":100},
       {"id":"L","action":"ALLOW","dst_ip":"10.0.0.0/24","protocol":"any","priority":50},
       {"id":"A","action":"ALLOW","dst_ip":"any","protocol":"ARP","priority":50}],
       "ids_signatures":[{"id":"S","pattern_type":"watch","match_criteria":{"dst_ip":"35.201.97.85","protocol":"TCP","dst_port":443},"severity":"high"}],
       "ips_actions":[]}' \
  http://127.0.0.1:8080/firewall/install
```
Dans **T2 (`mininet>`)** :
```
mininet> h0 hping3 -S -c 8 -i u400000 -p 443 35.201.97.85
```
**À voir dans T1 :**
```
🚨 IDS (defense-in-depth) : 35.201.97.85 AUTORISÉ par le firewall mais RÉPUTATION
   malveillante → BLOCK posé (l'IDS rattrape ce que le FW a laissé passer)
```
Vérifier (dans T2) :
```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep '950,ip,nw_dst=35.201.97.85'   # actions=drop
```
→ le C2 que le firewall avait laissé passer est maintenant **jeté** par l'IDS.
> Honnêteté : un cohost INCONNU de la réputation reste une fuite (aucun signal ne le
> distingue dans les traces) → sa détection = perspective SNI/DPI.

---

## SCÉNARIO C — Mini-démo stateful (Wireshark) : h0→h1 OK, h1→h0 bloqué

```
T1  cd /home/kali/Desktop/projet_chaine
    sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --stateful

T2  cd /home/kali/Desktop/projet_chaine
    sudo python3 deploy_mini_demo.py                          # → mininet>  (1 switch, h0, h1)

T3  cd /home/kali/Desktop/projet_chaine
    curl -X POST -H 'Content-Type: application/json' \
      -d @stateful_poc/demo_chain.json http://127.0.0.1:8080/firewall/install
```
Dans T2 (`mininet>`) :
```
mininet> sh wireshark -i s1-eth1 &      # côté h0   (ou : h0 wireshark &)
mininet> sh wireshark -i s1-eth2 &      # côté h1   (ou : h1 wireshark &)
mininet> h0 ping -c 3 10.0.0.2          # h0 → h1 : PASSE
mininet> h1 ping -c 3 10.0.0.1          # h1 → h0 : BLOQUÉ (100% perte)
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=1
```
Filtre Wireshark : `icmp.type==8 && ip.src==10.0.0.2` → présent côté h1, **absent** côté h0.

---

## SCÉNARIO D — PoC stateful pur (conntrack, hors os-ken)
```
sudo bash stateful_poc/conntrack_poc.sh          # monte + teste (intérieur↔extérieur)
sudo bash stateful_poc/conntrack_poc.sh clean    # démonte
```

---

## Arrêter proprement
```
mininet> exit           # dans T2
Ctrl+C                  # dans T1 (et T4 si lancé)
sudo mn -c              # nettoyage OVS si besoin
```
