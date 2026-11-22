"""benchmark/eval_end2end.py — Évaluation de BOUT EN BOUT (rejeu du trafic).

On teste le SYSTÈME, pas le modèle : la chaîne (liste blanche du comportement de
l'app) laisse-t-elle passer son trafic normal et bloque-t-elle une déviation ?

Protocole (rejeu à sec, sans réseau live) :
  1. Construire la liste blanche à partir de la MOITIÉ des flux de l'app (train).
  2. Rejouer l'AUTRE moitié (hold-out, jamais vue) → doit PASSER.
  3. Rejouer le trafic d'une AUTRE application → doit être BLOQUÉ (déviation).

Matrice de confusion (positif = déviation / à bloquer) :
        laissé passer     bloqué
  app normale (hold-out)   TN          FP   (fausse alerte)
  autre app (déviation)    FN (raté)   TP

On dérive exactitude, précision, rappel, FPR, FNR — en POURCENTAGE.
La clé de comparaison (ip / port) change le compromis : c'est la granularité.
"""
from __future__ import annotations
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools.behavior_traces import load_outbound, _TRACES


def _flows(app):
    m = sorted(_TRACES.glob(f"{app}*.csv"))
    return load_outbound(m[0]) if m else []


def evaluate(app, other, level="ip"):
    f = _flows(app)
    train, test = f[::2], f[1::2]                       # moitié / moitié
    key = (lambda x: x["ip"]) if level == "ip" else (lambda x: x["port"])
    allowed = {key(x) for x in train}

    TN = sum(1 for x in test if key(x) in allowed)      # normal laissé passer ✅
    FP = len(test) - TN                                 # normal bloqué ❌
    dev = _flows(other)
    FN = sum(1 for x in dev if key(x) in allowed)       # déviation laissée passer ❌
    TP = len(dev) - FN                                  # déviation bloquée ✅

    tot = TP + TN + FP + FN
    pct = lambda n, d: round(100 * n / d, 1) if d else 0.0
    return {
        "app": app, "other": other, "level": level,
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "accuracy": pct(TP + TN, tot),
        "precision": pct(TP, TP + FP),
        "recall": pct(TP, TP + FN),
        "FPR": pct(FP, FP + TN),
        "FNR": pct(FN, FN + TP),
        "n_normal": len(test), "n_deviation": len(dev),
    }


def show(r):
    print(f"\n Chaîne de « {r['app']} »  vs  trafic de « {r['other']} »  (clé = {r['level']})")
    print(f"   trafic normal (hold-out) : {r['n_normal']} flux   ·   déviation : {r['n_deviation']} flux")
    print(f"   ┌────────────────────────┬─────────────┬──────────┐")
    print(f"   │                        │ laissé pass.│  bloqué  │")
    print(f"   │ normal (hold-out)      │  TN={r['TN']:<6} │ FP={r['FP']:<4} │")
    print(f"   │ déviation (autre app)  │  FN={r['FN']:<6} │ TP={r['TP']:<4} │")
    print(f"   └────────────────────────┴─────────────┴──────────┘")
    print(f"   exactitude {r['accuracy']}%  ·  précision {r['precision']}%  ·  rappel {r['recall']}%"
          f"  ·  FPR {r['FPR']}%  ·  FNR {r['FNR']}%")


if __name__ == "__main__":
    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    other = sys.argv[2] if len(sys.argv) > 2 else "lequipe"
    for level in ("ip", "port"):
        show(evaluate(app, other, level))
