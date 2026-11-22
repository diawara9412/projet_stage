#!/usr/bin/env python3
"""eval_e2e_chain.py — ÉVAL DE BOUT EN BOUT AVEC MÉTRIQUES, par LLM.

Les agents (LLM + outils + fallback) génèrent la VRAIE chaîne à partir du profil
train-half ; on teste la chaîne GÉNÉRÉE sur (bénin hold-out + 7 C2 réels + malware
synthétique) avec la logique /16 du contrôleur → matrice de confusion. On compare
les modèles LLM + le taux de repli (firewall) + les erreurs LLM rattrapées par les outils.

Différence avec eval_llm_classify.py : ici ce n'est pas le LLM qui classe les IP,
c'est la CHAÎNE produite par le pipeline complet des agents qui décide.

Usage : python3 benchmark/eval_e2e_chain.py
"""
import sys, os, json, subprocess, pathlib, re
_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from benchmark.eval_malware import gen_malware, SEED

REAL = [(c["c2_ip"], c.get("c2_domain"))
        for c in json.loads((_ROOT / "benchmark/results/mischief_c2.json").read_text())]
KEYS = list(dict.fromkeys(re.findall(r"gsk_[A-Za-z0-9]+", (_ROOT / ".env").read_text())))
MODELS = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant",
          "openai/gpt-oss-120b", "meta-llama/llama-4-scout-17b-16e-instruct"]
APPS = ["dropbox", "faceswitch", "lequipe", "viber"]
WORKER = _ROOT / "benchmark/_e2e_worker.py"


def p16(ip):
    return ".".join(ip.split(".")[:2])


def automate_ips(app):
    d = json.loads((_ROOT / f"automates/{app}_whitelist.json").read_text())
    ips = [(t.get("network_call") or {}).get("ip") for t in d.get("transitions", [])]
    return sorted({ip for ip in ips if isinstance(ip, str) and ip.count(".") == 3})


TEST = {}
for app in APPS:
    ips = automate_ips(app); train, drift = ips[::2], ips[1::2]
    TEST[app] = {"train": train, "drift": drift,
                 "mal": REAL + gen_malware(train, len(drift), SEED)}


def matrix(pl):
    TP = sum(1 for p, l in pl if p == 1 and l == 1)
    FP = sum(1 for p, l in pl if p == 1 and l == 0)
    TN = sum(1 for p, l in pl if p == 0 and l == 0)
    FN = sum(1 for p, l in pl if p == 0 and l == 1)
    tot = TP + FP + TN + FN or 1
    acc = (TP + TN) / tot
    pr = TP / (TP + FP) if TP + FP else 0
    rec = TP / (TP + FN) if TP + FN else 0
    f1 = 2 * pr * rec / (pr + rec) if pr + rec else 0
    fpr = FP / (FP + TN) if FP + TN else 0
    return dict(TP=TP, FP=FP, TN=TN, FN=FN, acc=acc, pr=pr, rec=rec, f1=f1, fpr=fpr)


def eval_chain(allow16, app):
    t = TEST[app]; pl = []
    for ip in t["drift"]:                       # bénin (0)
        pl.append((0 if p16(ip) in allow16 else 1, 0))
    for ip, _ in t["mal"]:                      # malveillant (1)
        pl.append((0 if p16(ip) in allow16 else 1, 1))
    return pl


# ── baseline IDÉALE : /16 sur le profil train (chaîne parfaite = eval_16) ──
ideal = matrix(sum((eval_chain({p16(x) for x in TEST[app]["train"]}, app) for app in APPS), []))
rows = [("IDÉALE  (/16 sur profil train)", ideal, None, None)]

# ── par modèle : worker en sous-processus (sa propre clé) → chaîne générée ──
for i, model in enumerate(MODELS):
    env = dict(os.environ, WORKER_MODEL=model, SUPERVISOR_MODEL=model,
               GROQ_API_KEY=(KEYS[i % len(KEYS)] if KEYS else ""))
    print(f"  … génération par les agents avec {model}", file=sys.stderr, flush=True)
    try:
        r = subprocess.run([sys.executable, "-u", str(WORKER)], env=env,
                           capture_output=True, text=True, timeout=900)
        line = [l for l in r.stdout.splitlines() if l.startswith("###JSON###")]
        data = json.loads(line[0][len("###JSON###"):]) if line else {}
        if not line:
            print("    (pas de JSON) stderr:", (r.stderr or "")[-200:], file=sys.stderr)
    except Exception as e:
        print(f"    échec worker: {e}", file=sys.stderr); data = {}

    pl = []; fw_llm = fw_fb = errs = 0
    for app in APPS:
        d = data.get(app, {})
        pl += eval_chain({p16(x) for x in d.get("allow_ips", [])}, app)
        fw = (d.get("agents", {}) or {}).get("firewall", {}) or {}
        if fw.get("source") == "llm":
            fw_llm += 1
        elif fw.get("source"):
            fw_fb += 1
        if isinstance(fw.get("errors"), int):
            errs += fw["errors"]
    nfw = fw_llm + fw_fb
    rows.append((model, matrix(pl), (fw_fb / nfw if nfw else 0.0), errs))

# ── affichage ──
print("\nÉVAL DE BOUT EN BOUT — la CHAÎNE générée par les agents décide (par LLM)")
print("train-half → agents génèrent la chaîne → test (bénin hold-out + 7 C2 réels + malware) · logique /16")
print("4 apps : dropbox, faceswitch, lequipe, viber · positif = malveillant\n")
hdr = (f"{'modèle (générateur de chaîne)':<40}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}"
       f"{'acc':>6}{'prec':>6}{'rec':>6}{'F1':>6}{'FPR':>6}{'repliFW':>8}{'errLLM':>7}")
print(hdr); print("-" * len(hdr))
best = max(rows[1:], key=lambda r: (r[1]['f1'], r[1]['pr']))[0] if len(rows) > 1 else None
for name, m, fb, errs in rows:
    star = "  <=" if name == best else ""
    fbs = "     —" if fb is None else f"{fb*100:>6.0f}%"
    ers = "     —" if errs is None else f"{errs:>6}"
    print(f"{name:<40}{m['TP']:>4}{m['FP']:>4}{m['TN']:>4}{m['FN']:>4}"
          f"{m['acc']:>6.2f}{m['pr']:>6.2f}{m['rec']:>6.2f}{m['f1']:>6.2f}{m['fpr']:>6.2f}{fbs}{ers}{star}")
print(f"\nMeilleur (F1) : {best}")
print("repliFW = % d'apps où l'agent Firewall est tombé en déterministe · "
      "errLLM = erreurs LLM (firewall) rattrapées par les outils.")
print("Ligne IDÉALE = chaîne parfaite (/16 sur profil) ; l'écart mesure la perte due à la génération.")
