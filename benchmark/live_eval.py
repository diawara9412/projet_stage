#!/usr/bin/env python3
"""
benchmark/live_eval.py — Évaluation LIVE de bout en bout (vrai switch + boucle).

Pré-requis lancés : contrôleur --loop, Mininet --nat, profil lequipe déployé, service.
On rejoue depuis h0 un trafic LABELLISÉ à travers s1, on laisse la BOUCLE décider
(table-miss→contrôleur→Redis→/16→règle), puis on lit le VERDICT RÉEL sur les flows
posés sur s1 → matrice de confusion en conditions réelles.

Classes : bénin (vraies IP lequipe) · malware RÉEL (C2 Mischief) · malware co-hébergé
(synthétique dans un /16 de lequipe = cas dur) · malware non-lié (autre plage).
"""
from __future__ import annotations
import json
import pathlib
import random
import subprocess
import sys
import time

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
import redis
from whitelist.profile_builder import build_profile

SW = "s1"


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout


def h0():
    o = sh("ps ax | grep 'mininet:h0$' | grep -v grep | awk '{print $1}'").split()
    return o[0] if o else None


def probe(pid, ip, port=443):
    subprocess.run(["mnexec", "-a", pid, "bash", "-c",
                    f"hping3 -S -c 2 -i u200 -p {port} {ip} >/dev/null 2>&1"],
                   capture_output=True)


def flows():
    return sh(f"ovs-ofctl -O OpenFlow13 dump-flows {SW}")


def verdict(ip, dump):
    """Verdict RÉEL du switch pour cette IP, d'après les flows installés."""
    for line in dump.splitlines():
        if f"nw_dst={ip}" in line or f"nw_dst={ip}/" in line:
            if "priority=950" in line:
                return "BLOCK"
            # ALLOW (prio 100) : NORMAL (mono-switch), steering output:<port> (--sfc),
            # OU redirection conntrack ct(...) (--stateful). Les trois = autorisé.
            if "priority=100" in line and ("NORMAL" in line or "output:" in line or "ct(" in line):
                return "ALLOW"
    return "BLOCK"   # aucune règle → table-miss → fail-closed → bloqué


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="lequipe", help="app dont la whitelist est déployée")
    args = ap.parse_args()

    pid = h0()
    if not pid:
        print("❌ h0 absent (Mininet lancé ?)"); return 1
    subprocess.run(["mnexec", "-a", pid, "bash", "-c", "ip route replace default via 10.0.0.254"],
                   capture_output=True)
    r = redis.Redis(host="127.0.0.1", port=6379, db=0)
    rnd = random.Random(7)

    leq = sorted(build_profile(args.app).ips)
    p16 = lambda ip: ".".join(ip.split(".")[:2])
    nb = min(10, len(leq))
    benign = rnd.sample(leq, nb)                                   # vraies IP de l'app → ALLOW
    real = [c["c2_ip"] for c in json.loads((_ROOT/"benchmark/results/mischief_c2.json").read_text())]
    # co-hébergé : dans un /16 de l'app (cas dur)
    cohost = []
    for _ in range(4):
        b = rnd.choice(leq).split("."); cohost.append(f"{b[0]}.{b[1]}.{rnd.randint(0,255)}.{rnd.randint(1,254)}")
    # non lié : plage random hors app (= AMBIGU pour le mode hybride : ni /16 ni réputation)
    pref = {p16(x) for x in leq}
    unrel = []
    while len(unrel) < 4:
        ip = f"{rnd.randint(11,223)}.{rnd.randint(0,255)}.{rnd.randint(0,255)}.{rnd.randint(1,254)}"
        if p16(ip) not in pref: unrel.append(ip)

    tests = ([(ip, "benign") for ip in benign] + [(ip, "mal_real") for ip in real]
             + [(ip, "mal_cohost") for ip in cohost] + [(ip, "mal_unrel") for ip in unrel])

    print("=" * 78)
    print(f"  ÉVAL LIVE — profil {args.app} · {len(tests)} flux rejoués depuis h0 → s1")
    print("=" * 78)
    # PHASE 1 : on déclenche l'escalade (la boucle décide + pose les règles)
    for ip, _ in tests:
        probe(pid, ip)
    t0 = time.time()
    while r.llen("sdn:anomalies") > 0 and time.time() - t0 < 120:
        time.sleep(1)
    time.sleep(3)
    # PHASE 2 : verdict réel sur les flows
    dump = flows()
    cm = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    byclass = {}
    for ip, lab in tests:
        v = verdict(ip, dump)
        mal = lab.startswith("mal")
        if mal and v == "BLOCK": cm["TP"] += 1; ok = "✓"
        elif mal and v == "ALLOW": cm["FN"] += 1; ok = "✗FN"
        elif not mal and v == "ALLOW": cm["TN"] += 1; ok = "✓"
        else: cm["FP"] += 1; ok = "✗FP"
        d = byclass.setdefault(lab, [0, 0])
        d[0] += 1; d[1] += (1 if (v == "BLOCK") == mal else 0)
    print("  Décision réelle du switch par classe (bloqués correctement / total) :")
    for lab, (n, good) in byclass.items():
        print(f"    {lab:<12} {good}/{n}")
    TP, FP, TN, FN = cm["TP"], cm["FP"], cm["TN"], cm["FN"]
    tot = TP + FP + TN + FN or 1
    acc = (TP + TN) / tot
    rec = TP / (TP + FN) if TP + FN else 0
    fnr = FN / (FN + TP) if FN + TP else 0
    print(f"\n  Matrice (positif=malveillant) : TP={TP} FP={FP} TN={TN} FN={FN}")
    print(f"  Accuracy={acc:.2f}  Recall(détection)={rec:.2f}  FNR(fuite)={fnr:.2f}")
    print("=" * 78)
    print("  Attendu : bénin ALLOW · C2 réel BLOCK · non-lié BLOCK · CO-HÉBERGÉ → FN (fuite /16)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
