# ryu_app/ — Contrôleur SDN OpenFlow (os_ken)

## Contexte

Ce dossier contient les applications du contrôleur SDN utilisées par la Phase 2 du projet.

**Ryu** (le contrôleur SDN d'origine) est incompatible avec Python 3.13 en raison
de changements dans `setuptools` (suppression de `get_script_args` dans la version récente).

**os_ken** est le fork officiel et maintenu de Ryu, développé par NTT Communications
dans le cadre d'OpenStack. Il offre **la même API** que Ryu mais supporte Python 3.8+.

---

## Versions

| Composant        | Version  | Notes                          |
|------------------|----------|--------------------------------|
| Python           | 3.13.12  | Via `/usr/bin/python3`         |
| os_ken           | 4.2.0    | Fork de Ryu, installé via pip  |
| Open vSwitch     | 3.7.1    | `ovs-vsctl`, `ovs-ofctl`       |
| Mininet          | 2.3.1b4  | Simulation réseau SDN          |
| OpenFlow         | 1.3      | `ofproto_v1_3`                 |

---

## Installation

```bash
# Ryu original — NE FONCTIONNE PAS sur Python 3.13
# pip3 install ryu  →  AttributeError: get_script_args (setuptools trop récent)

# os_ken — fork maintenu, fonctionne sur Python 3.13 ✓
pip3 install os-ken --break-system-packages

# Vérification
python3 -c "import os_ken; print('os_ken', os_ken.__version__)"
```

---

## Lancer le contrôleur

### Méthode standard

```bash
# Depuis la racine du projet
python3 ryu_app/run_manager.py ryu_app.simple_switch_13
```

Le contrôleur écoute sur :
- **Port 6653/TCP** — OpenFlow 1.3 (standard IANA)
- **Port 8080/TCP** — API REST (si l'app ofctl_rest est chargée)

### En arrière-plan

```bash
python3 ryu_app/run_manager.py ryu_app.simple_switch_13 &
RYU_PID=$!
echo "os_ken PID : $RYU_PID"
```

### Avec logs verbeux

```bash
python3 -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from os_ken.base.app_manager import AppManager
AppManager.run_apps(['ryu_app.simple_switch_13'])
"
```

---

## Arrêter le contrôleur

```bash
# Par PID (si lancé en arrière-plan)
kill $RYU_PID

# Par nom de processus
pkill -f "run_manager.py"

# Forcer si nécessaire
kill -9 $(pgrep -f run_manager)
```

---

## Connecter un switch Mininet à os_ken

```python
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import SingleSwitchTopo

topo = SingleSwitchTopo(k=2)
net = Mininet(
    topo=topo,
    controller=lambda name: RemoteController(
        name,
        ip="127.0.0.1",
        port=6653,
    ),
    switch=OVSSwitch,
    autoSetMacs=True,
)
net.start()
# ... tests ...
net.stop()
```

Ou en ligne de commande Mininet :

```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
```

---

## Comportement de blocage

`sdn_executor.py` installe les flows OpenFlow selon ces priorités (du plus fort
au plus faible) :

| Priorité | Type   | Action OpenFlow                          | Effet                                       |
|----------|--------|------------------------------------------|---------------------------------------------|
| **950**  | BLOCK  | instructions vides (DROP)                | **Jette le paquet en hardware** (bloque)    |
| 900      | IDS    | `OUTPUT:CONTROLLER`                      | Surveille (alerte +1) — voir ci-dessous     |
| 100      | ALLOW  | `OUTPUT:NORMAL`                          | Laisse passer (service légitime)            |
| 50       | LAN    | `OUTPUT:NORMAL`                          | Trafic interne (ARP, ICMP, IPv4 LAN)        |
| 1        | MAC    | sortie sur port appris                   | Apprentissage L2                            |
| 0        | miss   | `OUTPUT:CONTROLLER`                      | Table-miss → apprentissage                  |

### BLOCK direct : DROP sur le switch (depuis cette version)

Pour une menace **connue** (Tor, exfiltration, C2 identifiés par l'automate),
le switch jette le paquet **directement en hardware**, sans passer par le
contrôleur :

- La règle **BLOCK (priorité 950)** a des instructions vides → **DROP**.
- C'est la priorité la plus haute → elle gagne sur tout le reste.
- Le paquet est bloqué **dès le premier paquet**, de façon garantie et rapide.
- Le compteur `n_packets` du flow BLOCK fait office de **journal** : il compte
  le nombre de tentatives bloquées.

```bash
mininet> sh ovs-ofctl dump-flows s1 | grep "nw_dst=185.220.101.47"
 cookie=0xcafe0001, priority=950,ip,nw_dst=185.220.101.47 actions=drop  n_packets=N
```

### IDS : surveillance (priorité 900)

Les règles **IDS (priorité 900)** envoient le paquet au contrôleur
(`OUTPUT:CONTROLLER`), qui incrémente le compteur `ids_alerts` puis le forwarde
via `packet_in_handler`. Comme l'IDS est **sous** le BLOCK (950) :

- Pour une menace **avec** règle BLOCK : le DROP à 950 s'applique avant →
  l'IDS (900) n'est **jamais atteinte** pour elle. Le blocage prime.
- Pour une menace **sans** règle BLOCK (surveillance pure) : seule l'IDS (900)
  s'applique → le paquet est **loggé puis laissé passer**.

> **Pourquoi cette conception ?** Une tentative précédente plaçait l'IDS à 950
> avec `OUTPUT:CONTROLLER` pour « détecter et bloquer ». Mais le contrôleur
> réinjectait le paquet via l'apprentissage MAC (`packet_in_handler`), donc la
> menace n'était pas réellement bloquée. La solution fiable est le **DROP direct
> sur le switch** : le paquet ne quitte jamais le data-plane, le contrôleur n'est
> pas impliqué dans le blocage.

---

## Test d'intégration complet

```bash
# Nécessite sudo (Mininet crée des namespaces réseau)
sudo python3 test_ryu_basic.py
```

Ce script :
1. Lance os_ken en arrière-plan
2. Crée 1 switch OVS + 2 hosts via Mininet
3. Vérifie la connectivité (ping h1 → h2)
4. Affiche les flows OpenFlow installés par os_ken
5. Nettoie tout (try/finally — même en cas d'erreur)

---

## Vérification rapide sans sudo

Pour tester os_ken sans Mininet :

```bash
# Terminal 1 : lancer os_ken
python3 ryu_app/run_manager.py ryu_app.simple_switch_13 &

# Terminal 2 : vérifier le port + handshake OpenFlow
ss -tlnp | grep 6653   # doit afficher LISTEN sur 6653
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 6653), timeout=3)
hello = bytes([0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00])
s.send(hello)
resp = s.recv(256)
print('os_ken répond :', resp.hex())
# Attendu : 04 00 00 08 ... (HELLO) + 04 05 00 08 ... (FEATURES_REQUEST)
s.close()
"
```

---

## Différences os_ken vs Ryu

| Aspect        | Ryu (original)             | os_ken (fork)                |
|---------------|----------------------------|------------------------------|
| Maintenu      | Non (dernier commit 2021)  | Oui (NTT Communications)     |
| Python 3.10+  | ✗ Non                      | ✓ Oui                        |
| Python 3.13   | ✗ Non                      | ✓ Oui (testé)                |
| Import        | `from ryu.xxx import yyy`  | `from os_ken.xxx import yyy` |
| Launcher      | `ryu-manager app.py`       | `python3 ryu_app/run_manager.py app` |
| API OpenFlow  | Identique                  | Identique                    |
| Port défaut   | 6653                       | 6653                         |

**Migration Ryu → os_ken** : remplacer tous les imports `from ryu.` par `from os_ken.`.

---

## Problèmes rencontrés et solutions

### 1. Ryu ne s'installe pas sur Python 3.13

**Erreur :**
```
AttributeError: 'types.SimpleNamespace' object has no attribute 'get_script_args'
```

**Cause :** Ryu utilise `easy_install.get_script_args` via son `hooks.py`, supprimé dans
setuptools >= 60.0. Python 3.13 est livré avec setuptools 78.x.

**Solution :** Utiliser `os-ken` à la place (`pip3 install os-ken --break-system-packages`).

---

### 2. `os-ken-manager` absent du PATH après installation

**Cause :** os-ken 4.2.0 n'installe pas de script binaire `os-ken-manager`.

**Solution :** Utiliser `ryu_app/run_manager.py` qui appelle `AppManager.run_apps()` directement.

---

### 3. `ModuleNotFoundError: No module named 'ryu_app'`

**Cause :** Le dossier projet n'est pas dans `sys.path` lors du lancement.

**Solution :** `run_manager.py` ajoute automatiquement la racine du projet à `sys.path`.
En cas de lancement manuel : `PYTHONPATH=/home/kali/Desktop/projet python3 ...`

---

### 4. Test Mininet nécessite sudo

**Cause :** Mininet crée des network namespaces et des interfaces virtuelles (droits root).

**Solution :** `sudo python3 test_ryu_basic.py`

---

## Fichiers du dossier

| Fichier               | Rôle                                           |
|-----------------------|------------------------------------------------|
| `simple_switch_13.py` | App switch L2 apprenant OpenFlow 1.3 (test)    |
| `run_manager.py`      | Launcher os_ken (équivalent ryu-manager)        |
| `README.md`           | Cette documentation                             |
| *(à venir)*           | `sdn_executor.py` — App Phase 2 PolicyEnforcer  |
