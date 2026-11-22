#!/usr/bin/env python3
"""benchmark/replay_all.py — rejoue TOUTES les apps contre le profil déployé.

Usage (sudo, Mininet+contrôleur default-deny lancés, chaîne <profile> déployée) :
    sudo python3 benchmark/replay_all.py <profile> [app1 app2 ...]

Imprime une ligne par rejeu + une ligne ROWJSON exploitable pour la matrice.
"""
from __future__ import annotations
import json
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmark.traffic_test import host_pid, in_host, replay_app, SINK_IP


def main() -> int:
    profile = sys.argv[1] if len(sys.argv) > 1 else "lequipe"
    apps = sys.argv[2:] or ["lequipe", "viber", "dropbox", "faceswitch"]
    dev = host_pid("h0")
    sink = host_pid("h1")
    in_host(dev, f"ip route replace default via {SINK_IP}")
    in_host(dev, f"ping -c1 -W1 {SINK_IP} >/dev/null 2>&1")
    row = {"profile": profile, "accept": {}}
    for r in apps:
        rep = replay_app(dev, sink, r)
        row["accept"][r] = round(100 * rep["accept_rate"], 1)
        tag = "DIAG(légitime)" if r == profile else "anomalie"
        print(f"  profil={profile:<10} rejeu={r:<10} accept={100*rep['accept_rate']:5.1f}%  "
              f"({len(rep['passed'])}/{rep['n_triplets']})  [{tag}]")
    print("ROWJSON " + json.dumps(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
