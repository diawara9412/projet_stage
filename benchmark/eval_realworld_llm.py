#!/usr/bin/env python3
"""benchmark/eval_realworld_llm.py — Classification sur DATASET RÉEL, par LLM (7 modèles).

Bénin = IP légitimes réelles des apps (clouds/CDN) · Malveillant = IP C2/compromises
réelles (Emerging Threats + CINS). Toutes diverses → pas de /16 d'app : c'est un pur
test de JUGEMENT du LLM à partir des faits déterministes (ASN / org / réputation).
Abstention (UNCERTAIN) → ALLOW par défaut (conservateur), comptée à part.

Usage : python3 benchmark/eval_realworld_llm.py
"""
from __future__ import annotations
import sys, json, time, pathlib, re, itertools

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from enrichment.asn_resolver import AsnResolver
from enrichment.classifier import reputation_state

DATA = json.loads((_ROOT / "benchmark/dataset_realworld.json").read_text())   # [(ip,label)]
KEYS = list(dict.fromkeys(re.findall(r"gsk_[A-Za-z0-9]+", (_ROOT / ".env").read_text())))
MODELS = [
    "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
    "openai/gpt-oss-120b", "openai/gpt-oss-20b",
    "qwen/qwen3-32b", "qwen/qwen3.6-27b",
    "meta-llama/llama-4-scout-17b-16e-instruct",
]
labels = [l for _, l in DATA]

# ── évidence déterministe (cache) ──
_res = AsnResolver(); _ev = {}
def evidence(ip):
    if ip not in _ev:
        r = _res.resolve(ip)
        _ev[ip] = {"asn": r.asn, "org": r.org, "rep": reputation_state(r)}
    return _ev[ip]

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
SYS = ("Tu es un analyseur de securite reseau. A partir des FAITS reseau d'une "
       "destination, decide si elle est BENIGN (infrastructure legitime : CDN, cloud, "
       "service grand public), MALICIOUS (C2 / botnet / hote compromis) ou UNCERTAIN. "
       "Reputation: trusted=org de confiance, untrusted=mauvaise reputation, "
       "neutral=org quelconque, unknown=non resolu. "
       "Reponds UNIQUEMENT par un mot: BENIGN, MALICIOUS ou UNCERTAIN.")

_pool = {}; _vcache = {}; _rr = itertools.count()
def _llm(model, k):
    key = (model, k)
    if key not in _pool:
        _pool[key] = ChatGroq(api_key=KEYS[k], model=model, temperature=0.0,
                              request_timeout=30, max_retries=1)
    return _pool[key]

def verdict(model, ip):
    ck = (model, ip)
    if ck in _vcache:
        return _vcache[ck]
    ev = evidence(ip)
    msg = f"IP={ip} ASN={ev['asn']} organisation={ev['org']} reputation={ev['rep']}"
    v = None
    start = next(_rr) % len(KEYS)
    for j in range(len(KEYS)):
        llm = _llm(model, (start + j) % len(KEYS))
        try:
            out = llm.invoke([SystemMessage(content=SYS), HumanMessage(content=msg)],
                             config={"timeout": 30}).content.upper()
            hm, hb = "MALICIOUS" in out, "BENIGN" in out
            v = 1 if (hm and not hb) else 0 if (hb and not hm) else None
            break
        except Exception:
            continue
    _vcache[ck] = v
    return v

def metrics(preds):
    TP = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
    FP = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
    TN = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 0)
    FN = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)
    tot = TP + FP + TN + FN or 1
    acc = (TP + TN) / tot
    pr = TP / (TP + FP) if TP + FP else 0
    rec = TP / (TP + FN) if TP + FN else 0
    f1 = 2 * pr * rec / (pr + rec) if pr + rec else 0
    fpr = FP / (FP + TN) if FP + TN else 0
    return dict(TP=TP, FP=FP, TN=TN, FN=FN, acc=acc, pr=pr, rec=rec, f1=f1, fpr=fpr)

print(f"\nCLASSIFICATION SUR DATASET RÉEL — {len(MODELS)} LLM  (N={len(DATA)} : "
      f"{labels.count(0)} bénins réels + {labels.count(1)} malveillants réels ET+CINS)")
print("verdict = LLM sur faits déterministes (ASN/org/réputation) · positif = malveillant\n")
hdr = (f"{'modèle':<42}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}"
       f"{'acc':>6}{'prec':>6}{'rec':>6}{'F1':>6}{'FPR':>6}{'abst':>6}{'t':>6}")
print(hdr); print("-" * len(hdr), flush=True)

rows = []
for model in MODELS:
    print(f"  … {model}", file=sys.stderr, flush=True)
    preds, ab, t0 = [], 0, time.time()
    for ip, _ in DATA:
        v = verdict(model, ip)
        if v is None:
            v = 0; ab += 1                     # abstention -> ALLOW (bénin) par défaut
        preds.append(v)
    m = metrics(preds); dt = time.time() - t0
    rows.append((model, m, ab / len(DATA)))
    print(f"{model:<42}{m['TP']:>4}{m['FP']:>4}{m['TN']:>4}{m['FN']:>4}"
          f"{m['acc']:>6.2f}{m['pr']:>6.2f}{m['rec']:>6.2f}{m['f1']:>6.2f}{m['fpr']:>6.2f}"
          f"{ab/len(DATA)*100:>5.0f}%{dt:>5.0f}s", flush=True)

best = max(rows, key=lambda r: (r[1]['f1'], r[1]['pr']))[0]
print(f"\nMeilleur (F1) : {best}")
print("abst = % d'IP où le modèle s'est abstenu (compté comme ALLOW). positif = malveillant.")
