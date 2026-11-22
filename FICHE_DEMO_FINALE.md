# 🎬 FICHE DÉMO SOUTENANCE — commandes complètes (config + tests)

> Mode qui MARCHE : **`--two-switch`** (2 switches) **SANS** `--sfc --stateful`
> (le SFC détourne le trafic et casse l'arrivée à h1).
> Toujours faire : `cd /home/kali/Desktop/projet_chaine` · mot de passe sudo : `kali`
> `ovs-ofctl` : toujours avec **`-O OpenFlow13`**.

---

## 0. APRÈS UN REDÉMARRAGE — repartir de zéro

```bash
cd /home/kali/Desktop/projet_chaine
sudo mn -c
python3 -c "
import json
from tools.behavior_traces import enrich
from tools.behavior_chain import reference_chain
from tools.behavior_deploy import to_deployable
json.dump(to_deployable(reference_chain(enrich('viber'))), open('chain_viber.json','w'))
print('chain_viber.json OK')
"
ss -ltnp | grep -E ':8080|:6653'      # doit être VIDE (sinon sudo kill <pid>)
```

## 1. TERMINAL 1 — contrôleur (laisse tourner)
```bash
cd /home/kali/Desktop/projet_chaine
sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --default-deny --two-switch
```

## 2. TERMINAL 2 — réseau (laisse tourner, tu obtiens le prompt `mininet>`)
```bash
cd /home/kali/Desktop/projet_chaine
sudo python3 deploy_mini_demo.py --two-switch
```

## 3. TERMINAL 3 — les AGENTS génèrent + déploient
```bash
cd /home/kali/Desktop/projet_chaine
python3 demo_terminal.py viber --deploy
```

## 4. Vérifier les règles sur les DEUX switches
```bash
# dans mininet> (T2)
sh sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -i arp        # règle ARP présente ?
sh sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -c nw_dst     # ~90 règles ALLOW
sh sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep -c CONTROLLER # règles IDS (miroir)
```
- **s1** = pare-feu : `...nw_dst=<ip>,tp_dst=<port> actions=NORMAL` (ALLOW) + drop par défaut.
- **s2** = IDS : `...nw_dst=<ip>,tp_dst=443 actions=CONTROLLER:65535` (duplique vers le contrôleur).

---

## 5. PRÉPARER LE TEST (dans mininet>, une seule fois par session)
```bash
h1 ip addr add 54.231.34.80/32 dev h1-eth0        # une IP viber (AUTORISÉE)
h1 ip addr add 108.160.161.147/32 dev h1-eth0     # une IP dropbox (BLOQUÉE)
h1 python3 -m http.server 443 &                   # h1 répond sur 443
h0 ip route add 54.231.34.80/32 via 10.0.0.2g
h0 ip route add 108.160.161.147/32 via 10.0.0.2
```


## 6. TEST A — filtrage visible (curl, montre le SYN-ACK)
```bash
h0 curl -m3 -v http://54.231.34.80:443/           # viber  → Connected + 200   ✅
h0 curl -m3 -v http://108.160.161.147:443/        # dropbox → timed out         🚫
```

## 7. TEST B — les chiffres (rejeu massif)
```bash
h0 ip route replace default via 10.0.0.2          # h0 sort par h1
sudo python3 benchmark/traffic_test.py --profile viber --replay dropbox
```
→ tableau : viber ~100 % PASS, dropbox 100 % DROP.

## 8. PREUVE CHIFFRÉE (compteur de rejet)
```bash
sh sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "priority=0"   # n_packets du drop monte avec dropbox
```

---

## 📡 WIRESHARK — quelle interface regarder ?

Topologie : `h0 —[s1-eth1]— s1 (pare-feu) —[s1-eth2]— h1`

| Interface | = | Ce qu'on y voit |
|---|---|---|
| **s1-eth1** | côté **h0** (AVANT le pare-feu) | **TOUT** ce qui est envoyé (viber ET dropbox) |
| **s1-eth2** | côté **h1** (APRÈS le pare-feu) | **SEULEMENT** ce qui a **PASSÉ** (viber) |

### Le signe (regarde s1-eth2)
- **PASSÉ** ✅ → le trafic **APPARAÎT** sur `s1-eth2`.
- **BLOQUÉ** 🚫 → le trafic **N'APPARAÎT PAS** sur `s1-eth2` (mais il est sur `s1-eth1`).

### Les deux rejeux (Test B) — capture sur `s1-eth2`
```
Rejeu viber   → viber APPARAÎT sur s1-eth2      = PASSÉ ✅
Rejeu dropbox → dropbox N'APPARAÎT PAS sur s1-eth2 = BLOQUÉ 🚫
```
Filtres pour séparer :
```
ip.addr == 54.231.34.80        (viber   → présent)
ip.addr == 108.160.161.147     (dropbox → absent)
```

### Pour VOIR le SYN-ACK (Test A, curl) — capture sur `s1-eth1`
```
tcp.port == 443
viber   → SYN → SYN, ACK → ACK      (connexion établie) ✅
dropbox → que des SYN, jamais SYN-ACK (bloqué)          🚫
```

---

## 🗣️ Le fil à raconter au jury
1. Les **agents** génèrent la chaîne (Terminal 3, on voit chaque agent).
2. Le **contrôleur** la déploie → **s1 = pare-feu** (liste blanche), **s2 = IDS** (miroir vers contrôleur). `dump-flows s1` + `dump-flows s2`.
3. **Filtrage prouvé** : viber `Connected` / dropbox `timeout` (Test A), et sur Wireshark viber présent / dropbox absent sur `s1-eth2` (Test B), + compteur `drop` qui monte.

> Note honnête : h1 (puits) est sur s1, donc le trafic principal va h0→s1→h1 ; s2 inspecte via ses règles miroir. Le « → NAT » du schéma est la sortie Internet conceptuelle.
