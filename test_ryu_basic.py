#!/usr/bin/env python3
"""
test_ryu_basic.py — Test d'intégration os_ken (Ryu) + Mininet.

Lance os_ken en arrière-plan, crée un réseau Mininet avec 2 hosts et 1 switch
OVS connecté au contrôleur, vérifie la connectivité par pingall et affiche
les flows OpenFlow installés.

IMPORTANT : doit être lancé avec sudo car Mininet requiert les droits root.
    sudo python3 test_ryu_basic.py

Nettoyage garanti via try/finally : même en cas d'erreur, os_ken et Mininet
sont arrêtés proprement pour ne pas laisser de processus zombie.
"""

import logging
import os
import signal
import subprocess
import sys
import time

# ── Vérification des droits root ──────────────────────────────────────────
if os.geteuid() != 0:
    print("[ERREUR] Ce script nécessite sudo (Mininet requiert les droits root).")
    print("  Relancer avec : sudo python3 test_ryu_basic.py")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
RYU_APP_MODULE = "ryu_app.simple_switch_13"
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
RYU_STARTUP_WAIT = 3   # secondes d'attente pour que Ryu démarre
PING_TIMEOUT = 10      # secondes pour le pingall

ryu_proc: subprocess.Popen | None = None


def start_ryu() -> subprocess.Popen:
    """Lance os_ken en arrière-plan et retourne le processus."""
    logger.info("Démarrage de os_ken (simple_switch_13)...")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(PROJECT_ROOT, "ryu_app/run_manager.py"), RYU_APP_MODULE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=PROJECT_ROOT,
    )
    logger.info("os_ken PID : %d — attente %ds...", proc.pid, RYU_STARTUP_WAIT)
    time.sleep(RYU_STARTUP_WAIT)

    if proc.poll() is not None:
        out = proc.stdout.read().decode(errors="replace")
        raise RuntimeError(f"os_ken s'est arrêté prématurément :\n{out}")

    logger.info("os_ken démarré (PID %d)", proc.pid)
    return proc


def stop_ryu(proc: subprocess.Popen) -> None:
    """Arrête os_ken proprement."""
    if proc and proc.poll() is None:
        logger.info("Arrêt de os_ken (PID %d)...", proc.pid)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        logger.info("os_ken arrêté.")


def run_mininet_test() -> bool:
    """Lance Mininet, effectue pingall, affiche les flows. Retourne True si OK."""
    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.topo import SingleSwitchTopo

    setLogLevel("warning")

    logger.info("Création du réseau Mininet : 1 switch OVS + 2 hosts")
    topo = SingleSwitchTopo(k=2)
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name,
            ip=CONTROLLER_IP,
            port=CONTROLLER_PORT,
        ),
        switch=OVSSwitch,
        autoSetMacs=True,
    )

    try:
        net.start()
        logger.info("Réseau Mininet démarré.")

        # Attendre que les switches s'enregistrent auprès du contrôleur
        time.sleep(2)

        # ── Ping entre les 2 hosts ─────────────────────────────────────────
        logger.info("pingall en cours (timeout %ds)...", PING_TIMEOUT)
        h1, h2 = net.hosts[0], net.hosts[1]

        # ping direct h1 → h2
        result = h1.cmd(f"ping -c 3 -W {PING_TIMEOUT} {h2.IP()}")
        ping_ok = "3 received" in result or "2 received" in result or "1 received" in result

        print("\n" + "═" * 60)
        print("  RÉSULTAT PING h1 → h2")
        print("═" * 60)
        print(result)

        # ── Dump des flows installés ───────────────────────────────────────
        s1 = net.switches[0]
        flows_raw = s1.cmd(f"ovs-ofctl -O OpenFlow13 dump-flows {s1.name}")
        print("═" * 60)
        print(f"  FLOWS INSTALLÉS sur {s1.name}")
        print("═" * 60)
        print(flows_raw)

        # ── Évaluation ────────────────────────────────────────────────────
        nb_flows = flows_raw.count("priority=")
        print("═" * 60)
        if ping_ok:
            print(f"  ✓ Ping réussi — {nb_flows} flow(s) installé(s) par os_ken")
        else:
            print(f"  ✗ Ping échoué — {nb_flows} flow(s) installé(s)")
            print("    Vérifier que os_ken est bien connecté au switch.")
        print("═" * 60 + "\n")

        return ping_ok

    finally:
        logger.info("Arrêt du réseau Mininet...")
        net.stop()
        # Nettoyage des interfaces résiduelles
        subprocess.run(["mn", "--clean"], capture_output=True)
        logger.info("Mininet arrêté.")


def main() -> None:
    global ryu_proc

    print("\n os_ken (Ryu fork) + Mininet — Test d'intégration\n")

    try:
        # 1. Démarrer os_ken
        ryu_proc = start_ryu()

        # 2. Test Mininet
        success = run_mininet_test()

        # 3. Résultat
        if success:
            print("✓ Test d'intégration os_ken + Mininet réussi.\n")
            sys.exit(0)
        else:
            print("✗ Test échoué (ping non reçu).\n")
            sys.exit(1)

    except Exception as exc:
        logger.error("Erreur lors du test : %s", exc, exc_info=True)
        sys.exit(1)

    finally:
        # Nettoyage garanti même en cas d'erreur
        stop_ryu(ryu_proc)


if __name__ == "__main__":
    main()
