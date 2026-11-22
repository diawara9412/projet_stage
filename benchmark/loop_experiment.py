#!/usr/bin/env python3
"""
benchmark/loop_experiment.py — MÉTRIQUES de la boucle autonomique.

Rejoue TOUT le trafic d'une app B à travers la boucle fermée et chiffre :
  - escaladés (inconnus remontés à l'agent), % étendus vs bloqués,
  - délai moyen de décision (lu dans le log du service),
  - convergence : Δ table-miss au rejeu 1 (apprentissage) vs rejeu 2 (convergence → 0).

Pré-requis (boucle en marche) :
  T1 : sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --loop
  T2 : sudo python3 deploy_mini_demo.py --nat
  T3 : python3 architectures/supervisor/run_supervisor_test.py --deploy --automate <A>_whitelist
  T4 : python3 -u architectures/supervisor/supervisor_service.py --app <A> > /tmp/service.log

Usage : sudo python3 benchmark/loop_experiment.py --profile lequipe --replay viber
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

import redis
from whitelist.profile_builder import build_profile

SWITCH = "s1"
QUEUE = "sdn:anomalies"
SERVICE_LOG = "/tmp/service.log"


def host_pid(h: str) -> str | None:
    out = subprocess.run(
        f"ps ax | grep 'mininet:{h}$' | grep bash | grep -v mnexec | grep -v grep | awk '{{print $1}}'",
        shell=True, capture_output=True, text=True).stdout.split()
    return out[0] if out else None


def in_host(pid: str, cmd: str) -> None:
    subprocess.run(["mnexec", "-a", pid, "bash", "-c", cmd], capture_output=True, text=True)


def _dump() -> str:
    return subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", SWITCH],
                          capture_output=True, text=True).stdout


def tablemiss_pkts() -> int:
    for line in _dump().splitlines():
        if "priority=0" in line:
            m = re.search(r"n_packets=(\d+)", line)
            return int(m.group(1)) if m else -1
    return -1


def n_allow() -> int:
    return sum(1 for l in _dump().splitlines() if "priority=100" in l and "actions=NORMAL" in l)


def n_block() -> int:
    return sum(1 for l in _dump().splitlines() if "priority=950" in l)


def replay(pid: str, triplets) -> None:
    for ip, port, proto in triplets:
        p = port if port else (53 if proto == "udp" else 80)
        opt = "--udp" if proto == "udp" else "-S"
        in_host(pid, f"hping3 {opt} -c 2 -i u200 -p {p} {ip} >/dev/null 2>&1")


def wait_drain(r, timeout: int = 600) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if r.llen(QUEUE) == 0:
            time.sleep(3)  # laisser finir le dernier redéploiement
            if r.llen(QUEUE) == 0:
                return True
        time.sleep(2)
    return False


def latencies() -> list[int]:
    try:
        return [int(m) for m in re.findall(r"\((\d+) ms\)", open(SERVICE_LOG).read())]
    except Exception:
        return []


def main() -> int:
    ap = argparse.ArgumentParser(description="Métriques de la boucle autonomique")
    ap.add_argument("--profile", default="lequipe")
    ap.add_argument("--replay", default="viber")
    args = ap.parse_args()

    r = redis.Redis(host="127.0.0.1", port=6379, db=0)
    pid = host_pid("h0")
    if not pid:
        print("❌ h0 introuvable — Mininet (T2) lancé ?")
        return 1
    in_host(pid, "ip route replace default via 10.0.0.254")  # sortie via nat0/s1

    trip = list(build_profile(args.replay).triplets)
    print(f"== Boucle autonomique : profil={args.profile} déployé, rejeu={args.replay} "
          f"({len(trip)} triplets) ==")

    lat_before = len(latencies())
    a0, b0, tm0 = n_allow(), n_block(), tablemiss_pkts()
    print(f"  état initial : ALLOW={a0}  BLOCK={b0}  table-miss_pkts={tm0}")

    print("  PHASE 1 — rejeu (apprentissage : les inconnus escaladent)…")
    replay(pid, trip)
    if not wait_drain(r):
        print("  ⚠️ file non vidée dans le délai — résultats partiels")
    a1, b1, tm1 = n_allow(), n_block(), tablemiss_pkts()

    print("  PHASE 2 — rejeu (convergence : tout doit matcher ALLOW ou DROP)…")
    replay(pid, trip)
    time.sleep(3)
    tm2 = tablemiss_pkts()

    ext, blk = a1 - a0, b1 - b0
    tot = ext + blk
    lat = latencies()[lat_before:]

    print("\n" + "=" * 60)
    print("  MÉTRIQUES — BOUCLE AUTONOMIQUE")
    print("=" * 60)
    print(f"  inconnus escaladés : {tot}")
    if tot:
        print(f"    • étendus (dérive légitime) : {ext}  ({100*ext/tot:.1f}%)")
        print(f"    • bloqués (DROP explicite)  : {blk}  ({100*blk/tot:.1f}%)")
    if lat:
        print(f"  délai de décision  : moy={sum(lat)/len(lat):.0f} ms  "
              f"min={min(lat)}  max={max(lat)}  (n={len(lat)})")
    print(f"  convergence        : Δtable-miss phase1={tm1-tm0}  →  phase2={tm2-tm1}  "
          f"(→0 = convergé)")
    print(f"  table flows        : ALLOW {a0}→{a1}   BLOCK {b0}→{b1}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
