#!/usr/bin/env python3
"""
benchmark/measure_network_cost_v2.py — COÛT & SCALABILITÉ, version robuste.

Corrige les 4 faiblesses de la v1 (revue interne) :
  (1) régime établi ≠ classifieur : on ajoute la LATENCE DU PREMIER PAQUET
      (cache datapath vidé avant l'envoi → upcall → classification complète) ;
  (2) le bourrage même-masque est le cas le + favorable : on compare
      MÊME-MASQUE vs MASQUES VARIÉS (le coût du classifieur dépend du nombre de
      tuples, pas du nombre de règles — tuple space search, Pfaff et al. NSDI'15) ;
  (3) référence absente de la figure : on mesure et on trace le COMMUTATEUR NU ;
  (4) 1 run/palier : on RÉPÈTE (moyenne ± écart-type → barres d'erreur).

Topologie : h0 ── s1 ── s2 ── h1 (émetteur → pare-feu → inspection → puits).
Usage :  sudo python3 benchmark/measure_network_cost_v2.py
Sorties : benchmark/figures/network_cost_v2.{json,png}
"""
from __future__ import annotations
import argparse, json, pathlib, re, statistics as st, subprocess, sys, time

try:
    from mininet.net import Mininet
    from mininet.topo import Topo
    from mininet.link import TCLink
    from mininet.log import setLogLevel
except Exception as e:
    sys.exit(f"Mininet requis (sudo) : {e}")

OF = ["-O", "OpenFlow13"]
OUT = pathlib.Path(__file__).resolve().parent / "figures" / "network_cost_v2.json"


class ChainTopo(Topo):
    def build(self):
        h0 = self.addHost("h0", ip="10.0.0.1/24")
        h1 = self.addHost("h1", ip="10.0.0.2/24")
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        self.addLink(h0, s1, cls=TCLink, bw=100)
        self.addLink(s1, s2, cls=TCLink, bw=100)
        self.addLink(s2, h1, cls=TCLink, bw=100)


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True)


def add_flows(sw, lines):
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".flows", delete=False) as f:
        f.write("\n".join(lines) + "\n"); path = f.name
    sh("ovs-ofctl", *OF, "add-flows", sw, path); os.unlink(path)


def dummy_rules(n, mode):
    """n règles de bourrage. mode='same' → 1 seul masque (/32,TCP,port).
    mode='varied' → longueurs de préfixe + protocoles + présence de port variés
    → nombreux tuples distincts (ce qui coûte au classifieur en espace utilisateur)."""
    out = []
    for i in range(n):
        a, b = divmod(i, 254)
        ip = f"10.200.{a % 254}.{b + 1}"
        if mode == "same":
            out.append(f"priority=50,ip,nw_dst={ip},tcp,tp_dst=443,actions=drop")
        else:
            plen = 8 + (i % 25)                     # /8../32  → 25 masques de préfixe
            proto = ("tcp", "udp")[i % 2]           # ×2 protocoles
            r = f"priority=50,{proto},nw_dst={ip}/{plen}"
            if i % 3 == 0:
                r += f",tp_dst={1024 + (i % 2000)}"  # champ port présent ou non
            out.append(r + ",actions=drop")
    return out


def set_baseline(switches):
    for sw in switches:
        sh("ovs-ofctl", *OF, "del-flows", sw)
        add_flows(sw, ["priority=0,actions=NORMAL"])


def set_secure(switches, n, mode):
    base = ["priority=100,arp,actions=NORMAL",
            "priority=100,ip,nw_dst=10.0.0.1,actions=NORMAL",
            "priority=100,ip,nw_dst=10.0.0.2,actions=NORMAL"]
    tail = ["priority=0,actions=drop"]
    for sw in switches:
        sh("ovs-ofctl", *OF, "del-flows", sw)
        add_flows(sw, base + dummy_rules(n, mode) + tail)


def n_masks(sw):
    """nb de masques (tuples) distincts dans la table OpenFlow de sw."""
    out = sh("ovs-ofctl", *OF, "dump-flows", sw).stdout
    masks = set()
    for l in out.splitlines():
        if "cookie=" not in l:
            continue
        m = l.split("actions=")[0]
        fields = re.findall(r"(nw_dst|tp_dst|arp|tcp|udp|icmp|ip)", m)
        masks.add(tuple(sorted(set(fields))) + (("/" + m.split("nw_dst=")[1].split("/")[1].split(",")[0])
                  if "nw_dst=" in m and "/" in m.split("nw_dst=")[1].split(",")[0] else "",))
    return len(masks)


def flush_dp():
    sh("ovs-appctl", "dpctl/del-flows")            # vide le cache megaflow du noyau


def steady_rtt(net, reps=5):
    h0, h1 = net.get("h0"), net.get("h1")
    vals = []
    for _ in range(reps):
        out = h0.cmd(f"ping -c 40 -i 0.01 -q {h1.IP()}")
        m = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
        if m:
            vals.append(float(m.group(1)))
    return (st.mean(vals), st.pstdev(vals)) if vals else (float("nan"), 0.0)


def first_packet_rtt(net, reps=15):
    """RTT du 1er paquet : cache datapath vidé → upcall → classification complète."""
    h0, h1 = net.get("h0"), net.get("h1")
    h0.cmd(f"ping -c 1 {h1.IP()} >/dev/null 2>&1")   # amorce ARP/voisin
    vals = []
    for _ in range(reps):
        flush_dp()
        out = h0.cmd(f"ping -c 1 -W 1 {h1.IP()}")
        m = re.search(r"time=([\d.]+)\s*ms", out)
        if m:
            vals.append(float(m.group(1)))
        time.sleep(0.05)
    return (st.mean(vals), st.pstdev(vals)) if vals else (float("nan"), 0.0)


def bw(net):
    h0, h1 = net.get("h0"), net.get("h1")
    h1.cmd("iperf3 -s -1 -D"); time.sleep(0.4)
    out = h0.cmd(f"iperf3 -c {h1.IP()} -t 4 -J 2>/dev/null")
    try:
        return round(json.loads(out)["end"]["sum_received"]["bits_per_second"] / 1e6, 1)
    except Exception:
        return float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="0,500,2000,4000")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--fp-reps", type=int, default=15)
    args = ap.parse_args()
    counts = [int(x) for x in args.rules.split(",")]

    setLogLevel("warning")
    net = Mininet(topo=ChainTopo(), link=TCLink, controller=None, autoSetMacs=True)
    net.start()
    for sw in ("s1", "s2"):
        sh("ovs-vsctl", "set-fail-mode", sw, "secure")
    S = ["s1", "s2"]
    res = {"baseline": {}, "steady": [], "first_packet": []}
    try:
        # ÉCHAUFFEMENT : stabilise htb (débit) et les tables MAC avant toute mesure
        set_baseline(S)
        h0, h1 = net.get("h0"), net.get("h1")
        h0.cmd(f"ping -c 20 {h1.IP()} >/dev/null 2>&1"); bw(net); bw(net)

        # (3) RÉFÉRENCE : commutateur nu (mesurée À CHAUD)
        set_baseline(S)
        net.get("h0").cmd(f"ping -c 2 {net.get('h1').IP()} >/dev/null 2>&1")
        r, sd = steady_rtt(net, args.reps); fp, fpsd = first_packet_rtt(net, args.fp_reps)
        res["baseline"] = {"rtt_ms": r, "rtt_sd": sd, "fp_ms": fp, "fp_sd": fpsd, "bw_mbps": bw(net)}
        print(f"RÉFÉRENCE (nu)  RTT={r:.3f}±{sd:.3f}  1er-paquet={fp:.3f}±{fpsd:.3f}  débit={res['baseline']['bw_mbps']}")

        # (1)(4) régime établi vs (2) même-masque / masques variés, avec répétitions
        print("\n-- RÉGIME ÉTABLI (cache noyau) : RTT & débit vs nb règles (même-masque) --")
        for n in counts:
            set_secure(S, n, "same")
            net.get("h0").cmd(f"ping -c 2 {net.get('h1').IP()} >/dev/null 2>&1")
            r, sd = steady_rtt(net, args.reps); b = bw(net); nf = sum(1 for l in sh("ovs-ofctl", *OF, "dump-flows", "s1").stdout.splitlines() if "cookie=" in l)
            res["steady"].append({"n": n, "flows": nf, "rtt_ms": r, "rtt_sd": sd, "bw_mbps": b})
            print(f"  n={n:>4} flows={nf:>4}  RTT={r:.3f}±{sd:.3f} ms  débit={b} Mb/s")

        print("\n-- PREMIER PAQUET (classifieur) : même-masque vs masques variés --")
        for mode in ("same", "varied"):
            for n in counts:
                set_secure(S, n, mode)
                nm = n_masks("s1")
                fp, fpsd = first_packet_rtt(net, args.fp_reps)
                res["first_packet"].append({"mode": mode, "n": n, "masks": nm, "fp_ms": fp, "fp_sd": fpsd})
                print(f"  {mode:>6} n={n:>4} masques≈{nm:>3}  1er-paquet={fp:.3f}±{fpsd:.3f} ms")
    finally:
        net.stop()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n✔ {OUT}")

    # figure : 3 panneaux
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        stdy = res["steady"]; xs = [r["n"] for r in stdy]
        fig, ax = plt.subplots(1, 3, figsize=(15, 4.2))
        # 1) RTT établi vs N + référence
        ax[0].errorbar(xs, [r["rtt_ms"] for r in stdy], yerr=[r["rtt_sd"] for r in stdy],
                       fmt="o-", color="#2b6cb0", capsize=3, label="chaîne active")
        ax[0].axhline(res["baseline"]["rtt_ms"], ls="--", color="#c0392b", label="commutateur nu (réf.)")
        ax[0].set(title="Régime établi : RTT vs nb règles", xlabel="règles", ylabel="RTT (ms)")
        ax[0].set_ylim(0, max(0.2, max(r["rtt_ms"] for r in stdy) * 1.4)); ax[0].legend(); ax[0].grid(alpha=.3)
        # 2) débit établi vs N + référence
        ax[1].plot(xs, [r["bw_mbps"] for r in stdy], "s-", color="#2e7d46", label="chaîne active")
        ax[1].axhline(res["baseline"]["bw_mbps"], ls="--", color="#c0392b", label="commutateur nu (réf.)")
        ax[1].set(title="Régime établi : débit vs nb règles", xlabel="règles", ylabel="débit (Mb/s)")
        ax[1].set_ylim(0, 100); ax[1].legend(); ax[1].grid(alpha=.3)
        # 3) premier paquet : même-masque vs variés
        for mode, col in (("same", "#2b6cb0"), ("varied", "#b7791f")):
            pts = [p for p in res["first_packet"] if p["mode"] == mode]
            ax[2].errorbar([p["n"] for p in pts], [p["fp_ms"] for p in pts],
                           yerr=[p["fp_sd"] for p in pts], fmt="o-", capsize=3, color=col,
                           label=("même masque" if mode == "same" else "masques variés"))
        ax[2].set(title="Premier paquet (classifieur) vs nb règles", xlabel="règles", ylabel="RTT 1er paquet (ms)")
        ax[2].legend(); ax[2].grid(alpha=.3)
        fig.suptitle("Coût d'application : régime établi (cache) vs premier paquet (classifieur)")
        fig.tight_layout(); fig.savefig(OUT.with_suffix(".png"), dpi=130)
        print(f"✔ {OUT.with_suffix('.png')}")
    except Exception as e:
        print(f"(figure : {e})")


if __name__ == "__main__":
    main()
