"""benchmark/e2e_live_matrix.py — évaluation LIVE de bout en bout, plusieurs paires.

Pour chaque paire (chaîne déployée A, déviation rejouée B) :
  1. génère la chaîne déployable de A depuis son COMPORTEMENT,
  2. la déploie sur le contrôleur SDN (REST),
  3. réarme le default-deny IP (au-dessus du steering L2),
  4. rejoue le trafic de A (doit passer) et de B (doit être bloqué) sur le VRAI réseau,
  5. calcule la matrice de confusion EN POURCENTAGE.

Positif = déviation (trafic à bloquer).
Usage (root) : sudo python3 benchmark/e2e_live_matrix.py viber:lequipe lequipe:viber …
"""
from __future__ import annotations
import json, pathlib, re, subprocess, sys, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DEMO = pathlib.Path("/home/kali/Desktop/demo_run")
REST = "http://127.0.0.1:8080/firewall/install"

ROW = re.compile(r"^(\S+)\s+(PROFIL|ANOMALIE)\s+\([^)]*\)\s+(\d+)\s+(\d+)\s+(\d+)")


def build_chain(app: str) -> pathlib.Path:
    from tools.behavior_traces import enrich
    from tools.behavior_chain import reference_chain
    from tools.behavior_deploy import to_deployable
    dep = to_deployable(reference_chain(enrich(app)))
    p = DEMO / f"chain_{app}_comportement.json"
    p.write_text(json.dumps(dep, ensure_ascii=False))
    return p


def deploy(path: pathlib.Path) -> dict:
    req = urllib.request.Request(REST, data=path.read_bytes(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def rearm_default_deny():
    subprocess.run(["ovs-ofctl", "add-flow", "s1",
                    "table=0,priority=5,ip,actions=drop", "-O", "OpenFlow13"],
                   capture_output=True)


def replay(profile: str, dev: str) -> dict:
    out = subprocess.run([sys.executable, str(ROOT / "benchmark/traffic_test.py"),
                          "--profile", profile, "--replay", dev],
                         capture_output=True, text=True, timeout=600).stdout
    res = {}
    for line in out.splitlines():
        m = ROW.match(line.strip())
        if m:
            app, role, tot, p, d = m.group(1), m.group(2), int(m.group(3)), int(m.group(4)), int(m.group(5))
            res[role] = {"app": app, "total": tot, "pass": p, "drop": d}
    return res


def metrics(prof: dict, anom: dict) -> dict:
    TN, FP = prof["pass"], prof["drop"]          # trafic normal : passé = TN, bloqué = FP
    FN, TP = anom["pass"], anom["drop"]          # déviation : passée = FN, bloquée = TP
    n_norm, n_dev = TN + FP, FN + TP
    pc = lambda a, b: round(100 * a / b, 1) if b else 0.0
    tot = n_norm + n_dev
    return {"TN%": pc(TN, n_norm), "FP%": pc(FP, n_norm),
            "FN%": pc(FN, n_dev), "TP%": pc(TP, n_dev),
            "exactitude": pc(TP + TN, tot),
            "precision": pc(TP, TP + FP), "rappel": pc(TP, TP + FN),
            "FPR": pc(FP, n_norm), "FNR": pc(FN, n_dev),
            "n_norm": n_norm, "n_dev": n_dev}


def main(pairs):
    rows = []
    for pair in pairs:
        a, b = pair.split(":")
        print(f"\n▶ chaîne={a}  déviation={b}", flush=True)
        try:
            p = build_chain(a)
            info = deploy(p)
            print(f"   déployé : {info.get('rules_configured')} règles, "
                  f"{info.get('flows_installed_on_hardware')} flows", flush=True)
            rearm_default_deny()
            r = replay(a, b)
            if "PROFIL" not in r or "ANOMALIE" not in r:
                print("   ⚠️ rejeu incomplet"); continue
            m = metrics(r["PROFIL"], r["ANOMALIE"])
            m["chaine"], m["deviation"] = a, b
            rows.append(m)
            print(f"   TN {m['TN%']}%  FP {m['FP%']}%  |  TP {m['TP%']}%  FN {m['FN%']}%  "
                  f"→ rappel {m['rappel']}%  FPR {m['FPR']}%", flush=True)
        except Exception as e:
            print(f"   ✗ échec : {e}", flush=True)
    (DEMO / "e2e_matrix.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1))
    print(f"\n→ {DEMO/'e2e_matrix.json'}")
    h = (f"{'chaîne':<12}{'déviation':<12}{'TN%':>7}{'FP%':>7}{'FN%':>7}{'TP%':>7}"
         f"{'exact.':>8}{'préc.':>8}{'rappel':>8}{'FPR':>7}{'FNR':>7}")
    print("\n" + h); print("-" * len(h))
    for m in rows:
        print(f"{m['chaine']:<12}{m['deviation']:<12}{m['TN%']:>7}{m['FP%']:>7}{m['FN%']:>7}"
              f"{m['TP%']:>7}{m['exactitude']:>8}{m['precision']:>8}{m['rappel']:>8}"
              f"{m['FPR']:>7}{m['FNR']:>7}")


if __name__ == "__main__":
    main(sys.argv[1:] or ["viber:lequipe"])
