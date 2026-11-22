#!/usr/bin/env python3
"""
benchmark/measure_install_time.py — TEMPS D'INSTALLATION des règles (au niveau OVS).

Mesure le coût de pose de N règles dans Open vSwitch, N ∈ {500,1000,2000,4000},
avec RÉPÉTITIONS (barres d'erreur), selon trois régimes :

  • BORNE BASSE  : un lot de flow-mods (add-flows <fichier>) — émission batchée ;
  • BORNE HAUTE  : une invocation ovs-ofctl par règle (fork+exec+connexion+flow-mod) ;
  • TÉMOIN no-op : N invocations « ovs-ofctl show » (fork+exec+connexion, AUCUNE
                   insertion) → isole le terme constant du coût d'insertion.

⚠️ Ces deux régimes ENCADRENT le contrôleur os-ken (qui émet un FlowMod par règle
sur une connexion persistante, sans spawn) ; ils ne le reproduisent pas. Le coût
bout-en-bout réel du contrôleur est mesuré à part (measure_osken_install.py).

Usage :  sudo python3 benchmark/measure_install_time.py
Sortie : benchmark/figures/install_time.{json,png}
"""
from __future__ import annotations
import json, pathlib, statistics as st, subprocess, tempfile, os, time

BR = "bmark0"
OF = ["-O", "OpenFlow13"]
OUT = pathlib.Path(__file__).resolve().parent / "figures" / "install_time.json"
COUNTS = [500, 1000, 2000, 4000]
REPS_BULK = 5
REPS_PERFLOW = 1      # borne haute lente (~20 min à 4000) ; le chiffre est accepté
REPS_NOOP = 2         # témoin : isole le terme constant fork+exec


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True)


def rules(n):
    return [f"priority=50,ip,nw_dst=10.200.{(i // 254) % 254}.{i % 254 + 1},"
            f"tcp,tp_dst=443,actions=drop" for i in range(n)]


def n_flows():
    return sum(1 for l in sh("ovs-ofctl", *OF, "dump-flows", BR).stdout.splitlines()
               if "cookie=" in l)


def timed_bulk(rs):
    with tempfile.NamedTemporaryFile("w", suffix=".flows", delete=False) as f:
        f.write("\n".join(rs) + "\n"); path = f.name
    t0 = time.perf_counter(); sh("ovs-ofctl", *OF, "add-flows", BR, path)
    dt = time.perf_counter() - t0; os.unlink(path)
    return dt


def timed_perflow(rs):
    t0 = time.perf_counter()
    for r in rs:
        sh("ovs-ofctl", *OF, "add-flow", BR, r)
    return time.perf_counter() - t0


def timed_noop(n):
    """N invocations sans insertion : mesure fork+exec+connexion (terme constant)."""
    t0 = time.perf_counter()
    for _ in range(n):
        sh("ovs-ofctl", *OF, "show", BR)
    return time.perf_counter() - t0


def stats(ts):
    return st.mean(ts), (st.pstdev(ts) if len(ts) > 1 else 0.0)


def main():
    sh("ovs-vsctl", "--if-exists", "del-br", BR)
    sh("ovs-vsctl", "add-br", BR)
    sh("ovs-vsctl", "set", "bridge", BR, "protocols=OpenFlow13")
    sh("ovs-vsctl", "set-fail-mode", BR, "secure")
    res = {"bulk": [], "perflow": [], "noop": []}
    try:
        print(f"== BORNE BASSE — lot (add-flows), {REPS_BULK} rép. ==")
        for n in COUNTS:
            rs = rules(n); ts = []
            for _ in range(REPS_BULK):
                sh("ovs-ofctl", *OF, "del-flows", BR); ts.append(timed_bulk(rs))
            nf = n_flows(); m, sd = stats(ts)
            res["bulk"].append({"n": n, "flows": nf, "s": m, "s_sd": sd,
                                "ms_per_rule": round(m / n * 1000, 3), "rules_per_s": round(n / m)})
            print(f"  n={n:>4} flows={nf:>4}  {m*1000:8.1f} ± {sd*1000:5.1f} ms  "
                  f"({m/n*1000:.3f} ms/règle · {n/m:,.0f} r/s)")

        print(f"\n== TÉMOIN no-op — N × 'show' (sans insertion), {REPS_NOOP} rép. ==")
        for n in COUNTS:
            ts = [timed_noop(n) for _ in range(REPS_NOOP)]
            m, sd = stats(ts)
            res["noop"].append({"n": n, "s": m, "s_sd": sd, "ms_per_call": round(m / n * 1000, 3)})
            print(f"  n={n:>4}  {m*1000:8.1f} ± {sd*1000:5.1f} ms  ({m/n*1000:.3f} ms/appel constant)")

        print(f"\n== BORNE HAUTE — process par règle, {REPS_PERFLOW} rép. ==")
        for n in COUNTS:
            ts = []
            for _ in range(REPS_PERFLOW):
                sh("ovs-ofctl", *OF, "del-flows", BR); ts.append(timed_perflow(rules(n)))
            m, sd = stats(ts)
            res["perflow"].append({"n": n, "s": m, "s_sd": sd,
                                   "ms_per_rule": round(m / n * 1000, 3), "rules_per_s": round(n / m)})
            print(f"  n={n:>4}  {m:7.2f} ± {sd:5.2f} s  ({m/n*1000:.1f} ms/règle · {n/m:,.0f} r/s)")
    finally:
        sh("ovs-vsctl", "--if-exists", "del-br", BR)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n✔ {OUT}")

    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7.5, 4.6))
        for key, lab, col, fmt in (("bulk", "borne basse (lot)", "#2e7d46", "o-"),
                                   ("noop", "témoin no-op (fork+exec)", "#888888", "^:"),
                                   ("perflow", "borne haute (process/règle)", "#c0392b", "s--")):
            d = res[key]; x = [r["n"] for r in d]
            y = [r["s"] * 1000 for r in d]; e = [r.get("s_sd", 0) * 1000 for r in d]
            ax.errorbar(x, y, yerr=e, fmt=fmt, capsize=3, color=col, label=lab)
        ax.set(title="Temps d'installation des règles vs taille de la politique",
               xlabel="nombre de règles", ylabel="temps d'installation (ms)")
        ax.set_yscale("log"); ax.grid(alpha=.3, which="both"); ax.legend()
        fig.tight_layout(); fig.savefig(OUT.with_suffix(".png"), dpi=130)
        print(f"✔ {OUT.with_suffix('.png')}")
    except Exception as e:
        print(f"(figure : {e})")


if __name__ == "__main__":
    main()
