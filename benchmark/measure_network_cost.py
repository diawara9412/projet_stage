#!/usr/bin/env python3
"""
benchmark/measure_network_cost.py — COÛT & SCALABILITÉ de la chaîne de sécurité.

Contrairement à la matrice de confusion (dont le blocage est analytiquement
attendu), ce banc mesure des grandeurs NON triviales, sur le réseau réel :

  1) COÛT DE LA SÉCURITÉ  : latence (RTT) et débit (iperf3) d'un commutateur nu
     (NORMAL) vs la chaîne active (default-deny + liste d'ALLOW + drop).
  2) SCALABILITÉ          : latence et débit en fonction du NOMBRE de règles
     installées dans le commutateur (0 → 2000), pour répondre à
     « et si la politique grossit (7 apps → des centaines de règles) ? ».

Topologie autonome (aucun contrôleur, règles posées via ovs-ofctl) :
    h0 (10.0.0.1) ── s1 (pare-feu) ── s2 (IDS) ── h1 (10.0.0.2)

Usage :  sudo python3 benchmark/measure_network_cost.py
         sudo python3 benchmark/measure_network_cost.py --rules 0,100,500,1000
Sortie : tableau console + benchmark/figures/network_cost.json (+ .png si matplotlib)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import statistics
import sys
import time

try:
    from mininet.net import Mininet
    from mininet.topo import Topo
    from mininet.link import TCLink
    from mininet.log import setLogLevel
except Exception as e:  # pragma: no cover
    sys.exit(f"Mininet requis (lancer avec sudo) : {e}")

OF = ["-O", "OpenFlow13"]
OUT = pathlib.Path(__file__).resolve().parent / "figures" / "network_cost.json"


class ChainTopo(Topo):
    """h0 ── s1 ── s2 ── h1 (la chaîne : filtrer puis inspecter)."""
    def build(self):
        h0 = self.addHost("h0", ip="10.0.0.1/24")
        h1 = self.addHost("h1", ip="10.0.0.2/24")
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        # liens à capacité fixe pour un débit comparable d'un run à l'autre
        self.addLink(h0, s1, cls=TCLink, bw=100)
        self.addLink(s1, s2, cls=TCLink, bw=100)
        self.addLink(s2, h1, cls=TCLink, bw=100)


def ofctl(sw: str, verb: str, *rest: str) -> str:
    # ovs-ofctl attend : <verbe> <switch> [règle]  (le switch juste après le verbe)
    import subprocess
    r = subprocess.run(["ovs-ofctl", *OF, verb, sw, *rest],
                       capture_output=True, text=True)
    if r.returncode != 0 and r.stderr.strip():
        print(f"    ! ovs-ofctl {verb} {sw}: {r.stderr.strip()[:80]}")
    return r.stdout


def flush(sw: str) -> None:
    ofctl(sw, "del-flows")


def set_baseline(switches) -> None:
    """Commutateur nu : tout est transféré en NORMAL (pas de sécurité)."""
    for sw in switches:
        flush(sw)
        ofctl(sw, "add-flow", "priority=0,actions=NORMAL")


def set_secure(switches, n_dummy: int = 0) -> None:
    """Chaîne active : ARP + paire autorisée en NORMAL, tout le reste DROP.
    n_dummy règles ALLOW factices (adresses jamais utilisées) pour tester la
    scalabilité : elles grossissent la table sans changer la connectivité."""
    import subprocess, tempfile, os
    for sw in switches:
        flush(sw)
        lines = ["priority=100,arp,actions=NORMAL",
                 "priority=100,ip,nw_dst=10.0.0.1,actions=NORMAL",
                 "priority=100,ip,nw_dst=10.0.0.2,actions=NORMAL"]
        # règles factices (liste blanche « grossie ») : priorité intermédiaire,
        # jamais matchées par le trafic 10.0.0.x réel → connectivité intacte.
        for i in range(n_dummy):
            a, b = divmod(i, 254)
            lines.append(f"priority=50,ip,nw_dst=10.200.{a % 254}.{b + 1},actions=drop")
        lines.append("priority=0,actions=drop")            # fermeture par défaut
        # installation EN MASSE (un seul appel) pour rester rapide même à N élevé
        with tempfile.NamedTemporaryFile("w", suffix=".flows", delete=False) as f:
            f.write("\n".join(lines) + "\n")
            path = f.name
        subprocess.run(["ovs-ofctl", *OF, "add-flows", sw, path],
                       capture_output=True, text=True)
        os.unlink(path)


def count_flows(sw: str) -> int:
    return sum(1 for l in ofctl(sw, "dump-flows").splitlines() if "cookie=" in l)


def measure_rtt(net, n: int = 50) -> tuple[float, float]:
    """RTT moyen (ms) et gigue (mdev) h0 → h1."""
    h0, h1 = net.get("h0"), net.get("h1")
    out = h0.cmd(f"ping -c {n} -i 0.01 -q {h1.IP()}")
    m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", out)
    return (float(m.group(2)), float(m.group(4))) if m else (float("nan"), float("nan"))


def measure_bw(net) -> float:
    """Débit TCP (Mbit/s) h0 → h1 via iperf3."""
    h0, h1 = net.get("h0"), net.get("h1")
    h1.cmd("iperf3 -s -1 -D")           # serveur, une connexion, daemon
    time.sleep(0.5)
    out = h0.cmd(f"iperf3 -c {h1.IP()} -t 4 -J 2>/dev/null")
    try:
        j = json.loads(out)
        return round(j["end"]["sum_received"]["bits_per_second"] / 1e6, 1)
    except Exception:
        return float("nan")


def bench(net, label: str, sw, n_dummy: int, secure: bool) -> dict:
    if secure:
        set_secure(sw, n_dummy)
    else:
        set_baseline(sw)
    net.get("h0").cmd(f"ping -c 2 {net.get('h1').IP()} >/dev/null 2>&1")  # amorce ARP/MAC
    rtt, jit = measure_rtt(net)
    bw = measure_bw(net)
    nfl = count_flows("s1")
    print(f"  {label:<34} RTT={rtt:6.3f} ms  gigue={jit:5.3f}  débit={bw:7.1f} Mb/s  "
          f"règles/s1={nfl}")
    return {"label": label, "secure": secure, "n_dummy": n_dummy,
            "rtt_ms": rtt, "jitter_ms": jit, "bw_mbps": bw, "flows_s1": nfl}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="0,100,500,1000,2000",
                    help="nombres de règles factices pour le test de scalabilité")
    args = ap.parse_args()
    rule_counts = [int(x) for x in args.rules.split(",")]

    setLogLevel("warning")
    net = Mininet(topo=ChainTopo(), link=TCLink, controller=None, autoSetMacs=True)
    net.start()
    # fail-mode secure : le switch n'agit QUE selon nos règles (pas de contrôleur)
    for sw in ("s1", "s2"):
        import subprocess
        subprocess.run(["ovs-vsctl", "set-fail-mode", sw, "secure"])
    switches = ["s1", "s2"]
    results: list[dict] = []
    try:
        print("\n=== 1) COÛT DE LA SÉCURITÉ (commutateur nu vs chaîne active) ===")
        results.append(bench(net, "Baseline (NORMAL, sans sécurité)", switches, 0, secure=False))
        results.append(bench(net, "Chaîne active (default-deny + ALLOW)", switches, 0, secure=True))

        print("\n=== 2) SCALABILITÉ (latence/débit vs nombre de règles) ===")
        for n in rule_counts:
            results.append(bench(net, f"Chaîne + {n} règles", switches, n, secure=True))
    finally:
        net.stop()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n✔ résultats → {OUT}")

    # figure (optionnelle)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        scal = [r for r in results if r["secure"] and r["label"].startswith("Chaîne +")]
        xs = [r["n_dummy"] for r in scal]
        fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
        ax[0].plot(xs, [r["rtt_ms"] for r in scal], "o-", color="#2b6cb0")
        ax[0].set(title="Latence vs taille de la politique", xlabel="nombre de règles",
                  ylabel="RTT (ms)")
        ax[1].plot(xs, [r["bw_mbps"] for r in scal], "s-", color="#2e7d46")
        ax[1].set(title="Débit vs taille de la politique", xlabel="nombre de règles",
                  ylabel="débit (Mb/s)")
        for a in ax:
            a.grid(alpha=.3)
        fig.tight_layout()
        png = OUT.with_suffix(".png")
        fig.savefig(png, dpi=130)
        print(f"✔ figure   → {png}")
    except Exception as e:
        print(f"(figure non générée : {e})")


if __name__ == "__main__":
    main()
