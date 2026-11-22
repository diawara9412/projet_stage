#!/usr/bin/env python3
"""benchmark/eval_llm_classify.py — MATRICE DE CONFUSION PAR LLM, SUR TOUS LES APPS.

L'AgentAnalyseur (LLM) classe chaque destination a partir de FAITS deterministes
et generalisables (ASN / org / reputation ASN-org), avec REPLI /16 quand il
s'abstient. On compare plusieurs modeles Groq de familles differentes.

Design (neuro-symbolique) :
    faits = resolve_asn(ip) -> {asn, org} + reputation_state(asn)   # deterministe
    verdict = LLM(faits)                                            # jugement
    si verdict == UNCERTAIN / echec -> verdict = heuristique /16    # filet de securite

Anti-fuite : on ne donne PAS au LLM le domaine synthetique (il encode le label),
ni une blocklist IP-exacte du jeu de test. Seulement ASN/org/reputation.

Le /16 est PAR APP -> on calcule par app puis on AGREGE (micro-moyenne : somme des
TP/FP/TN/FN sur tous les apps). Jeu de test identique a benchmark/eval_16_per_app.py.

Usage : python3 benchmark/eval_llm_classify.py            # tous les apps (defaut)
        python3 benchmark/eval_llm_classify.py dropbox    # un seul app
"""
from __future__ import annotations
import json, pathlib, sys, time

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from benchmark.eval_malware import APPS, load_named, gen_malware, SEED
from enrichment.asn_resolver import AsnResolver
from enrichment.classifier import reputation_state
import re as _re
_env = (_ROOT / ".env").read_text() if (_ROOT / ".env").exists() else ""
KEYS = list(dict.fromkeys(_re.findall(r"gsk_[A-Za-z0-9]+", _env)))   # toutes les cles (dont commentees)
if not KEYS:
    from config import GROQ_API_KEY
    KEYS = [GROQ_API_KEY]
print(f"  rotation sur {len(KEYS)} cle(s) Groq", file=sys.stderr)

REAL = [(c["c2_ip"], c.get("c2_domain"))
        for c in json.loads((_ROOT / "benchmark/results/mischief_c2.json").read_text())]

MODELS = [
    "llama-3.3-70b-versatile",                       # Meta Llama, gros
    "llama-3.1-8b-instant",                          # Meta Llama, petit
    "openai/gpt-oss-120b",                           # OpenAI (poids ouverts), gros
    "meta-llama/llama-4-scout-17b-16e-instruct",     # Meta Llama 4 (MoE)
    # "qwen/qwen3-32b",  # retire : 100% repli (=/16) + le plus lent, cf. run dropbox
]
ONLY = sys.argv[1] if len(sys.argv) > 1 else None


def p16(ip):
    return ".".join(ip.split(".")[:2])


# ── jeux de test par app (identiques a eval_16) ────────────────────────────
def build_apps():
    out = {}
    pool = [ONLY] if ONLY else APPS
    for app in pool:
        ips = sorted(load_named(app))
        if len(ips) < 16:
            continue
        train, drift = ips[::2], ips[1::2]
        mal = REAL + gen_malware(train, len(drift), SEED)
        pset = {p16(x) for x in train}
        test = [(ip, 0) for ip in drift] + [(ip, 1) for ip, _ in mal]
        out[app] = dict(test=test, pset=pset)
    return out


APPDATA = build_apps()
if not APPDATA:
    print("aucun app exploitable"); sys.exit(1)


# ── evidence deterministe par IP (cache global) ────────────────────────────
_res = AsnResolver()
_ev: dict[str, dict] = {}
def evidence(ip):
    if ip not in _ev:
        r = _res.resolve(ip)
        _ev[ip] = {"asn": r.asn, "org": r.org, "rep": reputation_state(r)}
    return _ev[ip]


# ── verdict LLM (cache par (modele, ip) : le prompt ne depend que de l'IP) ──
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
SYS = ("Tu es un analyseur de securite reseau. A partir des FAITS reseau d'une "
       "destination contactee par une application mobile legitime, decide si la "
       "destination est BENIGN (infrastructure legitime: CDN, cloud de l'app), "
       "MALICIOUS (C2 / exfiltration) ou UNCERTAIN (pas assez de signal). "
       "Reputation: trusted=org de confiance connue, untrusted=mauvaise reputation, "
       "neutral=org quelconque, unknown=non resolu. "
       "Reponds UNIQUEMENT par un mot: BENIGN, MALICIOUS ou UNCERTAIN.")
_vcache: dict[tuple, int | None] = {}
_llm_pool: dict[tuple, object] = {}
import itertools as _it
_rr = _it.count()

def _get_llm(model, kidx):
    k = (model, kidx)
    if k not in _llm_pool:
        _llm_pool[k] = ChatGroq(api_key=KEYS[kidx], model=model, temperature=0.0,
                                request_timeout=30, max_retries=1)
    return _llm_pool[k]

def llm_verdict(model, ip):
    ck = (model, ip)
    if ck in _vcache:
        return _vcache[ck]
    ev = evidence(ip)
    msg = f"IP={ip} ASN={ev['asn']} organisation={ev['org']} reputation={ev['rep']}"
    start = next(_rr) % len(KEYS)
    v = None
    for j in range(len(KEYS)):                     # rotation : essaie chaque cle
        llm = _get_llm(model, (start + j) % len(KEYS))
        try:
            out = llm.invoke([SystemMessage(content=SYS), HumanMessage(content=msg)],
                             config={"timeout": 30}).content.upper()
            has_m, has_b = "MALICIOUS" in out, "BENIGN" in out
            v = 1 if (has_m and not has_b) else 0 if (has_b and not has_m) else None
            break                                  # succes (verdict clair ou UNCERTAIN)
        except Exception:
            continue                               # quota/erreur -> cle suivante
    _vcache[ck] = v
    return v


def metrics(c):
    TP, FP, TN, FN = c["TP"], c["FP"], c["TN"], c["FN"]
    tot = TP + FP + TN + FN or 1
    acc = (TP + TN) / tot
    pr = TP / (TP + FP) if TP + FP else 0.0
    rec = TP / (TP + FN) if TP + FN else 0.0
    f1 = 2 * pr * rec / (pr + rec) if pr + rec else 0.0
    fpr = FP / (FP + TN) if FP + TN else 0.0
    return acc, pr, rec, f1, fpr


def h16(ip, pset):
    return 0 if p16(ip) in pset else 1


# ── baseline /16 agregee ───────────────────────────────────────────────────
def zero():
    return dict(TP=0, FP=0, TN=0, FN=0)

def accumulate(c, pred, label):
    if pred == 1 and label == 1: c["TP"] += 1
    elif pred == 1 and label == 0: c["FP"] += 1
    elif pred == 0 and label == 0: c["TN"] += 1
    else: c["FN"] += 1

base = zero()
for app, d in APPDATA.items():
    for ip, l in d["test"]:
        accumulate(base, h16(ip, d["pset"]), l)

per_app_prec: dict[str, dict[str, float]] = {}   # app -> {modele: prec}


def row_str(name, c, fbr, dt):
    acc, pr, rec, f1, fpr = metrics(c)
    return (f"{name:<42}{c['TP']:>4}{c['FP']:>4}{c['TN']:>4}{c['FN']:>4}"
            f"{acc:>6.2f}{pr:>6.2f}{rec:>6.2f}{f1:>6.2f}{fpr:>6.2f}"
            f"{fbr*100:>6.0f}%{dt:>6.0f}s")


# ── en-tete + baseline /16, imprimes TOUT DE SUITE (resultats incrementaux) ─
scope = ONLY if ONLY else f"{len(APPDATA)} apps"
Ntot = sum(len(d["test"]) for d in APPDATA.values())
print(f"\nMATRICE DE CONFUSION PAR LLM — {scope}  (positif=malveillant, N={Ntot} agrege)")
print("verdict = Analyseur(LLM sur ASN/org/reput) + repli /16 · micro-moyenne sur les apps\n")
hdr = (f"{'modele':<42}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}"
       f"{'acc':>6}{'prec':>6}{'rec':>6}{'F1':>6}{'FPR':>6}{'repli':>7}{'t':>7}")
print(hdr); print("-" * len(hdr))
print(row_str("(/16 seul)", base, 0.0, 0.0), flush=True)

rows = [("(/16 seul)", base, 0.0, 0.0)]
for model in MODELS:
    conf, fb, ntot, t0 = zero(), 0, 0, time.time()
    for app, d in APPDATA.items():
        appc = zero()
        for ip, l in d["test"]:
            v = llm_verdict(model, ip)
            if v is None:                    # abstention -> repli /16
                v = h16(ip, d["pset"]); fb += 1
            accumulate(conf, v, l); accumulate(appc, v, l); ntot += 1
            if ntot % 50 == 0:
                print(f"  … {model} : {ntot} IP traitees", file=sys.stderr, flush=True)
        per_app_prec.setdefault(app, {})[model] = metrics(appc)[1]
    rows.append((model, conf, fb / ntot, time.time() - t0))
    print(row_str(model, conf, fb / ntot, time.time() - t0), flush=True)   # ligne dès la fin

# ── recapitulatif ──────────────────────────────────────────────────────────
best = max(rows[1:], key=lambda r: metrics(r[1])[1:4])[0] if len(rows) > 1 else None
bacc, bpr, brec, bf1, bfpr = metrics(base)
print(f"\nMeilleure precision : {best}")
print(f"Baseline /16 : prec={bpr:.2f} FN={base['FN']} (fuite /16).")
print("Note: 'prec' seule peut tromper (flaguer peu -> prec haute, rec faible) : voir F1.")
print("      'repli' = % d'IP ou le LLM s'est abstenu (le /16 a tranche).")

# ── precision par app (annexe) ─────────────────────────────────────────────
print("\nPRECISION PAR APP (annexe) :")
short = {m: m.split("/")[-1][:14] for m in MODELS}
print(f"{'app':<12}" + "".join(f"{short[m]:>16}" for m in MODELS))
for app in APPDATA:
    print(f"{app:<12}" + "".join(f"{per_app_prec[app].get(m, 0):>16.2f}" for m in MODELS))
