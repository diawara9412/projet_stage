#!/usr/bin/env python3
"""benchmark/eval_complete_system.py — SYSTÈME COMPLET, par LLM, avec outil VirusTotal.

Chaque IP est jugée par le LLM à partir des faits déterministes ENRICHIS :
ASN / org / réputation + **VirusTotal** (nb de moteurs antivirus la classant
malveillante/suspecte sur ~90). Compare 7 LLM + baselines déterministes VT-seul.

Montre le CONTRASTE : sans VT (ASN/org) le LLM échoue (recall 0) ; avec VT il détecte.
→ la détection vient de l'OUTIL threat-intel, le LLM l'orchestre.

Prérequis : benchmark/vt_cache.json (via benchmark/vt_enrich.py).
Usage : python3 benchmark/eval_complete_system.py
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

DATA = json.loads((_ROOT / "benchmark/dataset_realworld.json").read_text())
VT = json.loads((_ROOT / "benchmark/vt_cache.json").read_text())
KEYS = list(dict.fromkeys(re.findall(r"gsk_[A-Za-z0-9]+", (_ROOT / ".env").read_text())))
MODELS = [
    "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
    "openai/gpt-oss-120b", "openai/gpt-oss-20b",
    "qwen/qwen3-32b", "qwen/qwen3.6-27b",
    "meta-llama/llama-4-scout-17b-16e-instruct",
]
labels = [l for _, l in DATA]

_res = AsnResolver(); _ev = {}
def evidence(ip):
    if ip not in _ev:
        r = _res.resolve(ip)
        v = VT.get(ip, {})
        _ev[ip] = {"asn": r.asn, "org": r.org, "rep": reputation_state(r),
                   "vt_m": v.get("malicious", 0), "vt_s": v.get("suspicious", 0)}
    return _ev[ip]

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
SYS = ("Tu es un analyseur de securite reseau. Decide si une destination est BENIGN "
       "(infrastructure legitime) ou MALICIOUS (C2 / botnet / hote compromis), ou UNCERTAIN. "
       "Tu disposes de : organisation/ASN (proprietaire de l'IP), reputation de l'org, et "
       "VirusTotal = nombre de moteurs antivirus (sur ~90) classant l'IP comme malveillante "
       "ou suspecte. Un nombre non nul de moteurs VirusTotal est un signal fort de malveillance. "
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
    e = evidence(ip)
    msg = (f"IP={ip} organisation={e['org']} ASN={e['asn']} reputation={e['rep']} "
           f"VirusTotal_malveillant={e['vt_m']} VirusTotal_suspect={e['vt_s']} (sur ~90 moteurs)")
    v = None; start = next(_rr) % len(KEYS)
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
    fnr = FN / (FN + TP) if FN + TP else 0
    return dict(TP=TP, FP=FP, TN=TN, FN=FN, acc=acc, pr=pr, rec=rec, f1=f1, fpr=fpr, fnr=fnr)

def prow(name, m, extra=""):
    print(f"{name:<40}{m['TP']:>4}{m['FP']:>4}{m['TN']:>4}{m['FN']:>4}"
          f"{m['acc']:>6.2f}{m['pr']:>6.2f}{m['rec']:>6.2f}{m['f1']:>6.2f}"
          f"{m['fpr']:>6.2f}{m['fnr']:>6.2f}{extra}", flush=True)

print(f"\nSYSTÈME COMPLET (LLM + outil VirusTotal) — {len(MODELS)} LLM · N={len(DATA)} "
      f"({labels.count(0)} bénins réels + {labels.count(1)} malveillants réels)\n")
hdr = (f"{'décideur':<40}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}"
       f"{'acc':>6}{'prec':>6}{'rec':>6}{'F1':>6}{'FPR':>6}{'FNR':>6}{'abst':>6}")
print(hdr); print("-" * len(hdr), flush=True)

# baselines déterministes VT-seul
prow("VT seul (>=1 moteur -> MALICIOUS)", metrics([1 if evidence(ip)["vt_m"] >= 1 else 0 for ip, _ in DATA]), "     —")
prow("VT seul (>=3 moteurs -> MALICIOUS)", metrics([1 if evidence(ip)["vt_m"] >= 3 else 0 for ip, _ in DATA]), "     —")

rows = []
for model in MODELS:
    print(f"  … {model}", file=sys.stderr, flush=True)
    preds, ab = [], 0
    for ip, _ in DATA:
        v = verdict(model, ip)
        if v is None:
            v = 0; ab += 1
        preds.append(v)
    m = metrics(preds); rows.append((model, m))
    prow(model, m, f"{ab/len(DATA)*100:>5.0f}%")

best = max(rows, key=lambda r: (r[1]['f1'], r[1]['pr']))[0]
print(f"\nMeilleur LLM (F1) : {best}")
print("Rappel : sans VT (ASN/org seul) tous les LLM étaient à recall 0. Avec VT, la détection vient de l'OUTIL.")
