"""benchmark/eval_behavior_pipeline.py — Éval fidèle au PIPELINE À 2 AGENTS.

Architecture de la nouvelle approche comportementale :
  Analyseur (déterministe)  → profil comportemental (behavior_traces)
  Firewall  (LLM)           → décide ALLOW / ALLOW_AND_INSPECT par service   [1 appel + reprises]
  IDS       (LLM)           → décide quelles boucles surveiller (signatures)  [1 appel + reprises]
  Vérificateur (déterministe) → contrôle la chaîne entière
  Déployeur (déterministe)

On instrumente CHAQUE agent séparément : appels, reprises, types d'erreurs, repli.
Le total d'appels est donc ≥ 2 (un par agent LLM), plus les reprises de correction.
"""
from __future__ import annotations
import json, os, pathlib, re, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tools.behavior_traces import enrich
from tools.behavior_chain import brief, reference_chain
from agents.chain_checker import check_chain, ERROR

MODELS = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile",
          "openai/gpt-oss-20b", "openai/gpt-oss-120b",
          "openai/gpt-oss-safeguard-20b", "qwen/qwen3.6-27b"]


def _key() -> str:
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    m = re.search(r"gsk_[A-Za-z0-9]+", env.read_text()) if env.exists() else None
    return os.environ.get("GROQ_API_KEY") or (m.group(0) if m else "")


def _parse(txt: str) -> dict | None:
    m = re.search(r"\{.*\}", txt, re.DOTALL)
    try:
        return json.loads(m.group(0)) if m else None
    except Exception:
        return None


def _observed(profile):
    return [s for s in profile["services"] if s.get("destinations")]


# ── Agent 1 : FIREWALL (LLM) — décide la politique d'accès ──────────────────
FW_PROMPT = """Tu es l'agent PARE-FEU. À partir du comportement réseau observé, décide pour CHAQUE service une action de LISTE BLANCHE.
- "ALLOW" pour un service normal.
- "ALLOW_AND_INSPECT" si le service est impliqué dans un enchaînement RARE (à surveiller).
- N'invente AUCUN service absent du comportement. Politique par défaut OBLIGATOIRE : "DENY".

COMPORTEMENT :
{brief}

Réponds UNIQUEMENT en JSON :
{{"default_action":"DENY","services":[{{"service":"<label exact>","action":"ALLOW|ALLOW_AND_INSPECT"}}]}}"""


def _fw_check(dec, profile):
    """Retourne une liste (catégorie, message) — vide si le pare-feu est correct."""
    obs = {s["label"] for s in _observed(profile)}
    beh = {s["label"] for s in profile["services"]}
    got = {d.get("service") for d in dec.get("services", [])}
    errs = []
    for m in sorted(obs - got):
        errs.append(("couverture", f"service « {m} » oublié"))
    for m in sorted(got - beh):
        errs.append(("invention", f"service « {m} » inventé (absent du comportement)"))
    if str(dec.get("default_action", "")).upper() != "DENY":
        errs.append(("default-deny", "la politique par défaut doit être DENY"))
    return errs


# ── Agent 2 : IDS (LLM) — décide quoi surveiller ────────────────────────────
IDS_PROMPT = """Tu es l'agent IDS. Voici les services mis sous surveillance par le pare-feu et les boucles observées.
Décide pour lesquels créer une signature de détection (beaconing). Il faut AU MOINS une signature par service sous surveillance.

Services sous surveillance : {watch}
Boucles observées (service : cadence médiane) : {loops}

Réponds UNIQUEMENT en JSON : {{"signatures":[{{"service":"<label>"}}]}}"""


def _ids_check(ids_dec, watch):
    got = {s.get("service") for s in ids_dec.get("signatures", [])}
    return [("inspect-sans-signature", f"service surveillé « {m} » sans signature IDS")
            for m in sorted(set(watch) - got)]


def _usage(resp):
    """Tokens d'un appel : (entrée, sortie)."""
    u = getattr(resp, "usage_metadata", None) or {}
    if u:
        return u.get("input_tokens", 0), u.get("output_tokens", 0)
    t = (getattr(resp, "response_metadata", {}) or {}).get("token_usage", {})
    return t.get("prompt_tokens", 0), t.get("completion_tokens", 0)


def _run_agent(llm, prompt, checker, max_attempts=3):
    """Un agent LLM avec sa boucle de correction. Retourne (décision, métriques)."""
    calls = retries = in_tok = out_tok = 0
    errors: list[str] = []                       # catégories rencontrées (dans l'ordre)
    dec, feedback = None, ""
    for _ in range(max_attempts):
        calls += 1
        try:
            resp = llm.invoke(prompt + ("\n\nCorrige ces erreurs :\n" + feedback if feedback else ""))
        except Exception as exc:
            errors.append(f"llm_error:{type(exc).__name__}"); break
        it, ot = _usage(resp); in_tok += it; out_tok += ot
        d = _parse(resp.content)
        if not d:
            errors.append("json-illisible"); retries += 1
            feedback = "Ta réponse n'était pas un JSON valide."; continue
        errs = checker(d)                        # [(catégorie, message), ...]
        if not errs:
            dec = d; break
        retries += 1; dec = d
        errors += [c for c, _ in errs]
        feedback = "\n".join("- " + m for _, m in errs)
    return dec, {"calls": calls, "retries": retries, "errors": errors,
                 "in_tok": in_tok, "out_tok": out_tok}


def _assemble(fw_dec, ids_dec, profile):
    by = {s["label"]: s for s in profile["services"]}
    fw = []
    for d in (fw_dec or {}).get("services", []):
        lbl = str(d.get("service", "")).strip()
        act = str(d.get("action", "ALLOW")).upper()
        act = act if act in ("ALLOW", "ALLOW_AND_INSPECT") else "ALLOW"
        svc = by.get(lbl)
        protos = (svc.get("protocols") if svc else None) or ["TCP"]
        for p in protos:
            fw.append({"service": lbl, "spec": svc["spec"] if svc else {"kind": "unknown"},
                       "protocol": p, "action": act,
                       "destinations": [x["ip"] for x in svc.get("destinations", [])] if svc else []})
    ids = []
    for s in (ids_dec or {}).get("signatures", []):
        lbl = str(s.get("service", "")).strip()
        svc = by.get(lbl)
        thr = (svc.get("periodicity", {}) or {}).get("median_interval_s") if svc else None
        ids.append({"service": lbl, "reason": "surveillance", "beaconing_threshold_s": thr})
    return {"app": profile["app_name"], "default_action": (fw_dec or {}).get("default_action", "?"),
            "firewall_rules": fw, "ids_signatures": ids}


def run(app, model):
    from langchain_groq import ChatGroq
    prof = enrich(app); ref = reference_chain(prof)
    llm = ChatGroq(model=model, api_key=_key(), temperature=0, request_timeout=45, max_retries=1)
    t0 = time.time()

    fw_dec, fwm = _run_agent(llm, FW_PROMPT.format(brief=brief(prof)), lambda d: _fw_check(d, prof))
    watch = [d["service"] for d in (fw_dec or {}).get("services", [])
             if str(d.get("action", "")).upper() == "ALLOW_AND_INSPECT"]
    loops = ", ".join(f"{l['service']}:{(next((x for x in prof['services'] if x['label']==l['service']),{}).get('periodicity',{}) or {}).get('median_interval_s')}"
                      for l in prof["loops"])
    ids_dec, idsm = _run_agent(llm, IDS_PROMPT.format(watch=watch or "(aucun)", loops=loops or "(aucune)"),
                               lambda d: _ids_check(d, watch))

    chain = _assemble(fw_dec, ids_dec, prof)
    rep = check_chain(chain, prof)
    fell_back = fw_dec is None or ids_dec is None or not rep["is_valid"]
    if fell_back:
        chain = ref
    # fidélité
    obs = {s["label"] for s in _observed(prof)}
    ref_act = {r["service"]: r["action"] for r in ref["firewall_rules"]}
    got_act = {r["service"]: r["action"] for r in chain["firewall_rules"]}
    cov = len({r["service"] for r in chain["firewall_rules"]} & obs) / max(1, len(obs))
    acc = sum(1 for s in obs if got_act.get(s) == ref_act.get(s)) / max(1, len(obs))
    # Matrice de confusion du JUGEMENT : positif = « service à surveiller »
    ref_ins = {s for s in obs if ref_act.get(s) == "ALLOW_AND_INSPECT"}
    mod_ins = {s for s in obs if got_act.get(s) == "ALLOW_AND_INSPECT"}
    tp = len(ref_ins & mod_ins); fn = len(ref_ins - mod_ins)
    fp = len(mod_ins - ref_ins); tn = len(obs - ref_ins - mod_ins)
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else \
         (0.0 if (prec == 0 or rec == 0) else None)
    from collections import Counter
    err = Counter(fwm["errors"] + idsm["errors"])
    err_str = ", ".join(f"{c}×{n}" if n > 1 else c for c, n in err.items()) or "—"
    return {"model": model, "fw_calls": fwm["calls"], "ids_calls": idsm["calls"],
            "total": fwm["calls"] + idsm["calls"], "retries": fwm["retries"] + idsm["retries"],
            "in_tok": fwm["in_tok"] + idsm["in_tok"], "out_tok": fwm["out_tok"] + idsm["out_tok"],
            "tokens": fwm["in_tok"] + idsm["in_tok"] + fwm["out_tok"] + idsm["out_tok"],
            "fell_back": fell_back, "coverage": round(cov, 2), "action": round(acc, 2),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "prec": prec, "rec": rec, "f1": f1,
            "seconds": round(time.time() - t0, 1), "errors": err_str}


def _f(x, w=5):
    return "  —  " if x is None else f"{x:>{w}.2f}"


if __name__ == "__main__":
    import json as _json
    apps = sys.argv[1].split(",") if len(sys.argv) > 1 else ["viber", "lequipe", "ratp"]
    out_rows = []
    for app in apps:
        print(f"\n=== App : {app}  (positif = service à surveiller) ===")
        h = (f"{'modèle':<28} {'cov':>4} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} "
             f"{'prec':>5} {'rec':>5} {'F1':>5} {'tok':>6} {'s':>5} {'repli':>5}")
        print(h); print("-" * len(h))
        for m in MODELS:
            r = run(app, m); r["app"] = app; out_rows.append(r)
            fb = "OUI" if r["fell_back"] else "non"
            print(f"{m:<28} {r['coverage']:>4.2f} {r['tp']:>3} {r['fp']:>3} {r['fn']:>3} "
                  f"{r['tn']:>3} {_f(r['prec'])} {_f(r['rec'])} {_f(r['f1'])} "
                  f"{r['tokens']:>6} {r['seconds']:>5.1f} {fb:>5}")
    pathlib.Path("benchmark/figures/evalC_results.json").write_text(
        _json.dumps(out_rows, ensure_ascii=False, indent=1))
    print("\n→ résultats sauvegardés : benchmark/figures/evalC_results.json")

