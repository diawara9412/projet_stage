#!/usr/bin/env python3
"""
ryu_app/run_manager.py — Launcher os_ken (équivalent de ryu-manager).

Usage :
    python3 ryu_app/run_manager.py ryu_app.simple_switch_13
    python3 ryu_app/run_manager.py ryu_app.simple_switch_13 --ofp-tcp-listen-port 6653

Les noms de modules sont relatifs au dossier racine du projet.
Ryu (os_ken) écoute sur le port 6653 (OpenFlow 1.3) par défaut.
"""

import logging
import sys
import pathlib

# Ajouter la racine du projet au path pour que "ryu_app.xxx" soit résolvable
_PROJECT_ROOT = str(pathlib.Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

if len(sys.argv) < 2:
    print("Usage: python3 run_manager.py <module.AppClass> [options]")
    print("  ex: python3 run_manager.py ryu_app.simple_switch_13")
    sys.exit(1)

# Filtrer les arguments os_ken (tout ce qui commence par --)
app_lists = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
extra_args = [arg for arg in sys.argv[1:] if arg.startswith("--")]

# ── Flag PROJET : --default-deny ──────────────────────────────────────────
# Consommé ici (transformé en variable d'environnement lue par sdn_executor),
# et NON transmis à oslo.config pour ne pas déclencher d'« unknown option ».
# Absent par défaut → sdn_executor reste en DEFAULT-ALLOW (compa A/B intacte).
import os
if "--default-deny" in extra_args:
    os.environ["SDN_DEFAULT_DENY"] = "1"
    extra_args = [a for a in extra_args if a != "--default-deny"]
    print("⚠️  Mode DEFAULT-DENY activé (liste blanche) : seules les ALLOW déployées passeront.")

# ── Flag PROJET : --loop (boucle autonomique) ─────────────────────────────
# Implique default-deny + escalade des inconnus : table-miss → Packet-In →
# file Redis (pour les agents), fail-closed. Consommé ici, non transmis à oslo.
if "--loop" in extra_args:
    os.environ["SDN_DEFAULT_DENY"] = "1"
    os.environ["SDN_LOOP_MODE"] = "1"
    extra_args = [a for a in extra_args if a != "--loop"]
    print("🔁 Mode BOUCLE activé : inconnus escaladés vers Redis (fail-closed).")

# ── Flag PROJET : --decide (le CONTRÔLEUR décide lui-même, niveau 2) ───────
# Implique --loop (table-miss → contrôleur) MAIS au lieu d'escalader vers Redis,
# le contrôleur tranche le déterministe (/16) et pose la règle directement.
if "--decide" in extra_args:
    os.environ["SDN_DEFAULT_DENY"] = "1"
    os.environ["SDN_LOOP_MODE"] = "1"
    os.environ["SDN_DECIDE"] = "1"
    extra_args = [a for a in extra_args if a != "--decide"]
    print("⚡ Mode DÉCISION CONTRÔLEUR : /16 tranché dans le contrôleur (fast-path).")

# ── Flag PROJET : --hybrid (contrôleur tranche le CLAIR, escalade l'AMBIGU) ─
# Le contrôleur décide /16-connu→ALLOW et réputation→BLOCK lui-même ; tout le
# reste (ni l'un ni l'autre = ambigu) est escaladé aux agents via Redis.
if "--hybrid" in extra_args:
    os.environ["SDN_DEFAULT_DENY"] = "1"
    os.environ["SDN_LOOP_MODE"] = "1"
    os.environ["SDN_HYBRID"] = "1"
    extra_args = [a for a in extra_args if a != "--hybrid"]
    print("🔀 Mode HYBRIDE : contrôleur tranche /16+réputation, escalade l'ambigu aux agents.")

# ── Flag PROJET : --two-switch (ÉTAPE 1 : chaîne FW + IDS) ─────────────────
# Sépare le rôle unique en deux switches : s1=FW (ALLOW/BLOCK+décisions),
# s2=IDS (surveillance seule). Corrige l'« IDS inerte » (le BLOCK 950 ne masque
# plus l'IDS 900, puisqu'ils sont sur deux switches). Réversible : sans le flag,
# comportement 100 % identique. À coupler avec deploy_mini_demo.py --two-switch.
if "--two-switch" in extra_args:
    os.environ["SDN_TWO_SWITCH"] = "1"
    extra_args = [a for a in extra_args if a != "--two-switch"]
    print("🔗 Mode DEUX SWITCHES : s1=FW (ALLOW/BLOCK), s2=IDS (surveillance, fait suivre).")

# ── Flag PROJET : --sfc (ÉTAPE 2 : chaînage explicite FW→IDS→NAT) ──────────
# Implique --two-switch. Remplace l'ALLOW en OFPP_NORMAL par un steering explicite
# par port (le FW pousse vers l'IDS ; l'IDS = bump-in-the-wire qui surveille et fait
# suivre vers le NAT). Réversible : sans le flag, on reste en Étape 1 (NORMAL).
if "--sfc" in extra_args:
    os.environ["SDN_TWO_SWITCH"] = "1"
    os.environ["SDN_SFC_STEERING"] = "1"
    extra_args = [a for a in extra_args if a != "--sfc"]
    print("🧭 Mode SFC (Étape 2) : chaînage explicite par steering FW→IDS→NAT.")

# ── Flag PROJET : --stateful (ÉTAPE 3 : conntrack natif via NXActionCT) ─────
# Sur le FW, l'ALLOW devient allow-then-inspect : l'aller passe par le conntrack
# (zone dédiée → n'affecte pas le NAT), décision d'état en table 1. Compatible
# --two-switch / --sfc (le forward garde steering/NORMAL, s2/IDS conservé).
# Réversible : sans le flag, aucune règle ct.
if "--stateful" in extra_args:
    os.environ["SDN_STATEFUL"] = "1"
    extra_args = [a for a in extra_args if a != "--stateful"]
    print("🧬 Mode STATEFUL (Étape 3) : ALLOW → conntrack natif (allow-then-inspect).")

# ── Flag PROJET : --inspect (POLITIQUE IDS : inspecter le trafic AUTORISÉ) ──
# Defense in depth : l'IDS surveille ce qui PASSE, pas ce qui est bloqué. Chaque
# règle ALLOW spécifique pose aussi un clone IDS sur s2 → l'IDS compte enfin le
# trafic permis. Réversible : sans le flag, l'IDS ne surveille que les signatures.
if "--inspect" in extra_args:
    os.environ["SDN_INSPECT_ALLOWED"] = "1"
    extra_args = [a for a in extra_args if a != "--inspect"]
    print("🔎 Politique IDS : INSPECTION du trafic autorisé (allow-then-inspect sur s2).")

# Passer les arguments supplémentaires à oslo.config
if extra_args:
    import sys as _sys
    _sys.argv = [_sys.argv[0]] + extra_args

from os_ken.base.app_manager import AppManager

if __name__ == "__main__":
    AppManager.run_apps(app_lists)
