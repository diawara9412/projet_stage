#!/usr/bin/env python3
"""
benchmark/measure_osken_install.py — TEMPS D'INSTALLATION BOUT-EN-BOUT PAR os-ken.

Contrairement à measure_install_time.py (qui chronomètre ovs-ofctl et ENCADRE le
contrôleur), ce banc mesure le VRAI chemin du système : un contrôleur os-ken
reçoit une chaîne de N règles par REST (/firewall/install) et émet un FlowMod par
règle sur une connexion OpenFlow persistante. On mesure :
  • t_REST     : durée de l'appel POST (traitement + émission des FlowMods) ;
  • t_installé : durée jusqu'à ce que les N règles apparaissent dans la table (dump-flows).

Montage : contrôleur os-ken (:6653/:8080) + un pont OVS connecté (pas de Mininet).
Usage :  sudo python3 benchmark/measure_osken_install.py
Sortie : benchmark/figures/osken_install.{json,png}
"""
from __future__ import annotations
import json, pathlib, signal, statistics as st, subprocess, sys, time, urllib.request

BR = "oskbench"
OF = ["-O", "OpenFlow13"]
CTRL = "http://127.0.0.1:8080"
ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = pathlib.Path(__file__).resolve().parent / "figures" / "osken_install.json"
COUNTS = [500, 1000, 2000, 4000]
REPS = 3


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True)


def chain(n):
    fr = [{"id": f"FW-{i:05d}", "dst_ip": f"10.201.{(i // 254) % 254}.{i % 254 + 1}",
           "protocol": "TCP", "dst_port": 443, "action": "ALLOW", "priority": 100}
          for i in range(n)]
    return {"chain_id": f"bench-{n}", "source_app_name": "bench",
            "global_risk_level": "low", "firewall_rules": fr,
            "ids_signatures": [], "ips_actions": []}


def post(path, obj=None, method="POST"):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(CTRL + path, data=data,
                                 headers={"Content-Type": "application/json"}, method=method)
    return urllib.request.urlopen(req, timeout=120).read().decode()


def chain_flows():
    """nb de règles de chaîne posées (cookie de chaîne → on compte les nw_dst 10.201)."""
    return sh("ovs-ofctl", *OF, "dump-flows", BR).stdout.count("nw_dst=10.201.")


def wait(cond, timeout, msg):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return True
        time.sleep(0.3)
    sys.exit(f"timeout: {msg}")


def main():
    # 1) contrôleur os-ken
    print("démarrage du contrôleur os-ken…")
    ctrl = subprocess.Popen(
        [sys.executable, "ryu_app/run_manager.py", "ryu_app.sdn_executor", "--default-deny"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {"rest": [], "installed": []}
    try:
        wait(lambda: sh("ss", "-ltn").stdout.find(":8080") >= 0, 25, "REST :8080")
        # 2) pont OVS connecté au contrôleur
        sh("ovs-vsctl", "--if-exists", "del-br", BR)
        sh("ovs-vsctl", "add-br", BR)
        sh("ovs-vsctl", "set", "bridge", BR, "protocols=OpenFlow13")
        sh("ovs-vsctl", "set-controller", BR, "tcp:127.0.0.1:6653")
        wait(lambda: "is_connected: true" in sh("ovs-vsctl", "-f", "table", "list",
             "controller").stdout.replace("\n", " ") or
             len(sh("ovs-ofctl", *OF, "dump-flows", BR).stdout.splitlines()) > 1,
             25, "switch connecté au contrôleur")
        time.sleep(1.0)
        print("contrôleur + switch prêts.\n")

        for n in COUNTS:
            rests, insts = [], []
            for _ in range(REPS):
                try:
                    post("/firewall/flush", method="DELETE")
                except Exception:
                    pass
                wait(lambda: chain_flows() == 0, 30, "flush")
                payload = chain(n)
                t0 = time.perf_counter()
                post("/firewall/install", payload)
                t_rest = time.perf_counter() - t0
                wait(lambda: chain_flows() >= n, 120, f"{n} règles posées")
                t_inst = time.perf_counter() - t0
                rests.append(t_rest); insts.append(t_inst)
            rm, rsd = st.mean(rests), (st.pstdev(rests) if REPS > 1 else 0)
            im, isd = st.mean(insts), (st.pstdev(insts) if REPS > 1 else 0)
            res["rest"].append({"n": n, "s": rm, "s_sd": rsd, "rules_per_s": round(n / rm)})
            res["installed"].append({"n": n, "s": im, "s_sd": isd, "rules_per_s": round(n / im)})
            print(f"  n={n:>4}  REST={rm*1000:7.1f}±{rsd*1000:5.1f} ms  "
                  f"installé={im*1000:7.1f}±{isd*1000:5.1f} ms  ({n/im:,.0f} règles/s)")
    finally:
        sh("ovs-vsctl", "--if-exists", "del-br", BR)
        ctrl.send_signal(signal.SIGINT); time.sleep(1); ctrl.kill()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n✔ {OUT}")
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7, 4.4))
        for key, lab, col in (("installed", "os-ken bout-en-bout (jusqu'à pose)", "#2b6cb0"),
                              ("rest", "appel REST (émission)", "#b7791f")):
            d = res[key]
            ax.errorbar([r["n"] for r in d], [r["s"] * 1000 for r in d],
                        yerr=[r["s_sd"] * 1000 for r in d], fmt="o-", capsize=3, color=col, label=lab)
        ax.set(title="Installation d'une chaîne par le contrôleur os-ken",
               xlabel="nombre de règles", ylabel="temps (ms)")
        ax.grid(alpha=.3); ax.legend()
        fig.tight_layout(); fig.savefig(OUT.with_suffix(".png"), dpi=130)
        print(f"✔ {OUT.with_suffix('.png')}")
    except Exception as e:
        print(f"(figure : {e})")


if __name__ == "__main__":
    main()
