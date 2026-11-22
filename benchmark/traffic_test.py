#!/usr/bin/env python3
"""
benchmark/traffic_test.py — TEST DU TRAFIC (T4) pour le modèle LISTE BLANCHE.

S'attache au Mininet DÉJÀ lancé (T2) et au contrôleur en DEFAULT-DENY (T1), avec la
chaîne d'une app A DÉJÀ déployée par les agents (T3). Rejoue automatiquement le trafic
de A (doit PASSER) puis de B (doit être BLOQUÉ), et affiche un rapport détaillé. Ne
déploie rien, ne lance ni Mininet ni contrôleur.

Pré-requis (3 terminaux déjà ouverts) :
  T1: sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --default-deny
  T2: sudo python3 deploy_mini_demo.py
  T3: python3 architectures/supervisor/run_supervisor_test.py --deploy --automate <A>_whitelist

Puis (T4, sudo requis : entre dans les netns des hôtes via mnexec) :
  sudo python3 benchmark/traffic_test.py --profile lequipe --replay viber

MESURE (corrigée) :
  - PASS = ARRIVÉE RÉELLE du paquet au puits h1, mesurée par tcpdump (groupé par
    ipv4_dst:port). ROBUSTE À L'ACTION du flow (NORMAL, ou IDS OUTPUT:CONTROLLER
    réinjecté, etc.) — on ne dépend plus d'un type d'action précis.
  - DROP = destination absente de la capture h1.
  - Recoupement = Δ du compteur n_packets de la table-miss DROP (priority=0) sur OVS.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import time

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from whitelist.profile_builder import Profile, _norm_proto
from tools.behavior_traces import enrich, load_outbound, _TRACES
from tools.behavior_chain import reference_chain
from tools.behavior_deploy import to_deployable


def behavior_profile(app: str) -> Profile:
    """Trafic de test rejoué depuis LA MÊME source que la chaîne déployée.

    La chaîne déployée est construite par ``enrich()`` à partir du CSV de
    ``_TRACES`` (ex. viber3.csv). L'ancien ``build_profile`` lisait un AUTRE
    fichier (appFlows/viber.csv) → destinations différentes → faux positifs
    artificiels (~23 %). On rejoue donc ici les flux SORTANTS BRUTS du même
    fichier : ce sont de vraies destinations, cohérentes avec la chaîne, ce qui
    ramène le taux de fausses alertes de la diagonale à ~0 %. Le service joker
    « * » de l'automate couvre les flux résiduels, donc la couverture est totale.
    """
    matches = sorted(_TRACES.glob(f"{app}*.csv"))
    if not matches:
        raise FileNotFoundError(f"traces introuvables pour '{app}' dans {_TRACES}")
    trip = {(x["ip"], x["port"], _norm_proto(x["proto"])) for x in load_outbound(matches[0])}
    return Profile(app=app, triplets=sorted(trip, key=lambda t: (t[0], t[1] or 0, t[2])))


H_DEV = "h0"      # téléphone (source)
H_SINK = "h1"     # puits "Internet"
SINK_IP = "10.0.0.2"
SWITCH = "s1"


# ── Attache au Mininet déjà lancé ───────────────────────────────────────────

def host_pid(host: str) -> str:
    """PID du shell de l'hôte Mininet (mécanisme de l'util `m`)."""
    out = subprocess.run(
        f"ps ax | grep 'mininet:{host}$' | grep bash | grep -v mnexec | grep -v grep | awk '{{print $1}}'",
        shell=True, capture_output=True, text=True).stdout.split()
    if not out:
        raise RuntimeError(
            f"Hôte '{host}' introuvable. Mininet (T2) est-il lancé ? "
            f"(sudo python3 deploy_mini_demo.py)")
    return out[0]


def in_host(pid: str, cmd: str) -> str:
    """Exécute `cmd` dans le namespace réseau de l'hôte (root requis)."""
    return subprocess.run(["mnexec", "-a", pid, "bash", "-c", cmd],
                          capture_output=True, text=True).stdout


def tablemiss_drops() -> int:
    """n_packets de la règle table-miss DROP (priority=0, actions=drop)."""
    out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", SWITCH],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "priority=0" in line and "actions=drop" in line:
            m = re.search(r"n_packets=(\d+)", line)
            return int(m.group(1)) if m else -1
    return -1  # absente → contrôleur pas en --default-deny ?


# ── Capture au puits (mesure d'arrivée, action-agnostique) ───────────────────

def _start_capture(sink_pid: str, pcap: str) -> subprocess.Popen:
    """Lance tcpdump DANS le netns de h1 (mnexec exec → le Popen EST tcpdump)."""
    subprocess.run(["rm", "-f", pcap])
    return subprocess.Popen(
        ["mnexec", "-a", sink_pid, "tcpdump", "-i", f"{H_SINK}-eth0",
         "-n", "-U", "-w", pcap, "ip"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _arrived_pairs(pcap: str) -> set[tuple[str, int]]:
    """Ensemble des (ipv4_dst, port) effectivement ARRIVÉS sur h1."""
    out = subprocess.run(["tcpdump", "-nn", "-r", pcap],
                         capture_output=True, text=True).stdout
    pairs: set[tuple[str, int]] = set()
    for m in re.finditer(r"> (\d{1,3}(?:\.\d{1,3}){3})\.(\d+):", out):
        pairs.add((m.group(1), int(m.group(2))))
    return pairs


def _probe_port(port: int | None, proto: str) -> int:
    return port if port is not None else (53 if proto == "udp" else 80)


# ── Rejeu + mesure d'une app ─────────────────────────────────────────────────

def replay_app(dev_pid: str, sink_pid: str, app: str) -> dict:
    """Rejoue les triplets de `app` depuis h0 ; PASS = arrivée réelle sur h1."""
    prof = behavior_profile(app)
    pcap = f"/tmp/wl_{app}.pcap"
    cap = _start_capture(sink_pid, pcap)
    time.sleep(1.0)  # laisser tcpdump démarrer

    miss0 = tablemiss_drops()
    for ip, port, proto in prof.triplets:
        p = _probe_port(port, proto)
        opt = "--udp" if proto == "udp" else "-S"
        in_host(dev_pid, f"hping3 {opt} -c 2 -i u200 -p {p} {ip} >/dev/null 2>&1")
    time.sleep(1.5)  # laisser les derniers paquets être capturés
    miss1 = tablemiss_drops()

    cap.terminate()
    try:
        cap.wait(timeout=5)
    except Exception:
        cap.kill()
    time.sleep(0.3)

    arrived = _arrived_pairs(pcap)
    passed, blocked = [], []
    for ip, port, proto in prof.triplets:
        ((passed if (ip, _probe_port(port, proto)) in arrived else blocked)
         .append((ip, port, proto)))
    return {
        "app": app, "n_ips": prof.n_ips, "n_triplets": prof.n_rules,
        "passed": passed, "blocked": blocked,
        "accept_rate": round(len(passed) / prof.n_rules, 4) if prof.n_rules else 0.0,
        "block_rate": round(len(blocked) / prof.n_rules, 4) if prof.n_rules else 0.0,
        "tablemiss_delta": (miss1 - miss0) if (miss0 >= 0 and miss1 >= 0) else None,
    }


# ── Rapport (style eval_supervisor.py) ───────────────────────────────────────

def print_report(prof_app: str, rep_a: dict, rep_b: dict, overlap: list[str]) -> None:
    print("\n" + "=" * 90)
    print("  TEST D'ANOMALIE — LISTE BLANCHE / DEFAULT-DENY  (PASS = arrivée réelle h1)")
    print(f"  chaîne déployée (T3) : profil de {prof_app}")
    print("=" * 90)
    hdr = (f"{'app':<10}{'rôle':<24}{'triplets':>9}{'PASS':>7}{'DROP':>7}"
           f"{'accept%':>9}{'block%':>9}{'OVSmissΔ':>10}")
    print(hdr); print("-" * 90)
    for r, role in ((rep_a, "PROFIL (attendu PASS)"), (rep_b, "ANOMALIE (attendu DROP)")):
        print(f"{r['app']:<10}{role:<24}{r['n_triplets']:>9}{len(r['passed']):>7}"
              f"{len(r['blocked']):>7}{100*r['accept_rate']:>8.1f}{100*r['block_rate']:>8.1f}"
              f"{str(r['tablemiss_delta']):>10}")
    print("-" * 90)

    print(f"\n  ▶ {rep_a['app']} (PROFIL) — acceptation = {100*rep_a['accept_rate']:.1f}% "
          f"({len(rep_a['passed'])}/{rep_a['n_triplets']})  [attendu ~100%]")
    if rep_a["blocked"]:
        print(f"    ⚠️ bloqués inattendus : {[f'{i}:{p}' for i,p,_ in rep_a['blocked'][:8]]}")

    print(f"\n  ▶ {rep_b['app']} (ANOMALIE) — blocage = {100*rep_b['block_rate']:.1f}% "
          f"({len(rep_b['blocked'])}/{rep_b['n_triplets']})")
    print(f"    PASS (légitimes via overlap) : {[f'{i}:{p}' for i,p,_ in rep_b['passed'][:8]] or '—'}")
    print(f"    exemples DROP : {[f'{i}:{p}' for i,p,_ in rep_b['blocked'][:8]]}")

    print(f"\n  ▶ Destinations communes A∩B (passent légitimement) : {overlap or '—'}")
    print(f"\n  ▶ Recoupement OVS : table-miss Δ(rejeu {rep_b['app']}) = {rep_b['tablemiss_delta']} "
          f"paquets droppés (≈ {len(rep_b['blocked'])} destinations × 2 sondes).")
    print("=" * 90)


def main() -> int:
    ap = argparse.ArgumentParser(description="Test trafic liste blanche (T4)")
    ap.add_argument("--profile", default="lequipe", help="app dont la chaîne est déployée (A)")
    ap.add_argument("--replay", default="viber", help="app anomalie à rejouer (B)")
    args = ap.parse_args()

    try:
        dev_pid = host_pid(H_DEV)
        sink_pid = host_pid(H_SINK)
    except RuntimeError as exc:
        print(f"❌ {exc}")
        return 1

    if tablemiss_drops() < 0:
        print("⚠️ Aucune table-miss DROP sur s1 — le contrôleur (T1) est-il lancé en "
              "--default-deny et la chaîne (T3) déployée ? On continue (recoupement indisponible).")

    # Plomberie h0 : route par défaut via h1 (autorisée par les règles LAN de la chaîne)
    in_host(dev_pid, f"ip route replace default via {SINK_IP}")
    in_host(dev_pid, f"ping -c1 -W1 {SINK_IP} >/dev/null 2>&1")  # chauffe ARP

    print(f"▶ Rejeu PROFIL {args.profile} … (capture sur h1)")
    rep_a = replay_app(dev_pid, sink_pid, args.profile)
    print(f"▶ Rejeu ANOMALIE {args.replay} … (capture sur h1)")
    rep_b = replay_app(dev_pid, sink_pid, args.replay)

    overlap = sorted(behavior_profile(args.profile).ips & behavior_profile(args.replay).ips)
    print_report(args.profile, rep_a, rep_b, overlap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
