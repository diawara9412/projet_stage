"""benchmark/eval_behavior_llm.py — Éval A+C : les LLM face au COMPORTEMENT.

Chaque modèle reçoit le briefing comportemental d'une application et décide la
POLITIQUE (pour chaque service : ALLOW / ALLOW_AND_INSPECT / omis, + default DENY).
Le code assemble la chaîne concrète (adresses, ports, seuils depuis le profil),
le vérificateur déterministe la contrôle ; en cas d'erreur on renvoie un retour
ciblé au modèle et on recommence (max 3), puis repli déterministe.

On INSTRUMENTE tout (demande de l'encadrant) :
  · appels au modèle, reprises de la boucle
  · TYPES d'erreurs rencontrées (couverture / invention / conflit / default-deny)
  · taux de REPLI  (le modèle a-t-il vraiment produit la chaîne, ou est-ce le code ?)
  · FIDÉLITÉ au comportement (couverture, exactitude des actions, inventions)
"""
from __future__ import annotations
import json, os, pathlib, re, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tools.behavior_traces import enrich
from tools.behavior_chain import brief, reference_chain
from agents.chain_checker import check_chain, ERROR

MODELS = [                     # identifiants valides sur le compte (vérifiés via /v1/models)
    "llama-3.1-8b-instant", "llama-3.3-70b-versatile",
    "openai/gpt-oss-20b", "openai/gpt-oss-120b",
    "openai/gpt-oss-safeguard-20b",
    "qwen/qwen3.6-27b",        # modèle à RAISONNEMENT (remplace qwen3-32b, déprécié)
]


def _key() -> str:
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    m = re.search(r"gsk_[A-Za-z0-9]+", env.read_text()) if env.exists() else None
    return os.environ.get("GROQ_API_KEY") or (m.group(0) if m else "")


PROMPT = """Tu génères une politique de sécurité en LISTE BLANCHE à partir du comportement réseau observé d'une application.

RÈGLES :
- Autorise CHAQUE service listé dans le comportement (action "ALLOW").
- Si un service est impliqué dans un enchaînement RARE, mets-le sous surveillance (action "ALLOW_AND_INSPECT").
- N'invente AUCUN service absent du comportement.
- La politique par défaut est OBLIGATOIREMENT "DENY".

COMPORTEMENT OBSERVÉ :
{brief}

Réponds UNIQUEMENT en JSON, sans texte autour :
{{"default_action":"DENY","services":[{{"service":"<label exact>","action":"ALLOW ou ALLOW_AND_INSPECT"}}, ...]}}
"""


def _parse(txt: str) -> dict | None:
    m = re.search(r"\{.*\}", txt, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _assemble(decisions: dict, profile: dict) -> dict:
    """Joint les décisions du LLM avec les données du profil → chaîne concrète."""
    by_label = {s["label"]: s for s in profile["services"]}
    loops = {l["service"] for l in profile["loops"]}
    fw, ids = [], []
    for d in decisions.get("services", []):
        lbl = str(d.get("service", "")).strip()
        act = str(d.get("action", "ALLOW")).strip().upper()
        act = act if act in ("ALLOW", "ALLOW_AND_INSPECT") else "ALLOW"
        svc = by_label.get(lbl)
        if not svc:                                   # service inventé : on le garde tel quel
            fw.append({"service": lbl, "spec": {"kind": "unknown"}, "protocol": "TCP",
                       "action": act, "destinations": []})
            continue
        for proto in (svc.get("protocols") or ["TCP"]):
            fw.append({"service": lbl, "spec": svc["spec"], "protocol": proto, "action": act,
                       "destinations": [x["ip"] for x in svc.get("destinations", [])]})
    # signatures ajoutées par le code (surveillé OU boucle à cadence) — c'est du concret, pas du jugement
    watched = {r["service"] for r in fw if r["action"] == "ALLOW_AND_INSPECT"}
    for lbl in watched | loops:
        svc = by_label.get(lbl)
        if not svc:
            continue
        p = svc.get("periodicity", {}) or {}
        ids.append({"service": lbl, "reason": "surveillance",
                    "beaconing_threshold_s": p.get("median_interval_s")})
    return {"app": profile["app_name"], "default_action": decisions.get("default_action", "?"),
            "firewall_rules": fw, "ids_signatures": ids}


def _feedback(rep: dict) -> str:
    errs = [i for i in rep["issues"] if i["severity"] == ERROR]
    lines = [f"- {i['message']}" + (f" → {i['suggested_fix']}" if i.get("suggested_fix") else "")
             for i in errs[:8]]
    return "La politique précédente comporte des erreurs à corriger :\n" + "\n".join(lines)


def _fidelity(chain: dict, ref: dict, profile: dict) -> dict:
    observed = {s["label"] for s in profile["services"] if s.get("destinations")}
    got = {r["service"] for r in chain["firewall_rules"]}
    ref_act = {r["service"]: r["action"] for r in ref["firewall_rules"]}
    got_act = {r["service"]: r["action"] for r in chain["firewall_rules"]}
    good_act = sum(1 for s in observed if got_act.get(s) == ref_act.get(s))
    return {
        "coverage": round(len(got & observed) / max(1, len(observed)), 3),
        "invented": len(got - {s["label"] for s in profile["services"]}),
        "action_accuracy": round(good_act / max(1, len(observed)), 3),
    }


def run(app: str, model: str, max_attempts: int = 3) -> dict:
    from langchain_groq import ChatGroq
    prof = enrich(app)
    ref = reference_chain(prof)
    llm = ChatGroq(model=model, api_key=_key(), temperature=0,
                   request_timeout=45, max_retries=1)
    base = PROMPT.format(brief=brief(prof))

    calls = retries = 0
    errors_seen: set[str] = set()
    fell_back = False
    rep = {"is_valid": False, "issues": []}
    chain = None
    t0 = time.time()
    feedback = ""
    for attempt in range(1, max_attempts + 1):
        calls += 1
        try:
            msg = base + ("\n\n" + feedback if feedback else "")
            out = llm.invoke(msg).content
        except Exception as exc:
            errors_seen.add(f"llm_error:{type(exc).__name__}")
            break
        dec = _parse(out)
        if not dec:
            errors_seen.add("unparsable_output")
            feedback = "Ta réponse n'était pas un JSON valide. Réponds UNIQUEMENT le JSON demandé."
            retries += 1
            continue
        chain = _assemble(dec, prof)
        rep = check_chain(chain, prof)
        if rep["is_valid"]:
            break
        retries += 1
        errors_seen |= {i["category"] for i in rep["issues"] if i["severity"] == ERROR}
        feedback = _feedback(rep)

    if chain is None or not rep.get("is_valid"):
        fell_back = True
        chain = ref                                   # repli déterministe
    fid = _fidelity(chain, ref, prof)
    return {"app": app, "model": model, "calls": calls, "retries": retries,
            "errors": sorted(errors_seen), "fell_back": fell_back,
            "valid": rep.get("is_valid", False), "score": rep.get("quality_score", 0),
            "seconds": round(time.time() - t0, 1), **fid}


if __name__ == "__main__":
    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    models = [sys.argv[2]] if len(sys.argv) > 2 else MODELS
    print(f"App : {app}\n")
    hdr = f"{'modèle':<42} {'appels':>6} {'repr.':>5} {'repli':>5} {'couv':>5} {'act':>5} {'inv':>3} {'s':>5}  erreurs"
    print(hdr); print("-" * len(hdr))
    for m in models:
        r = run(app, m)
        print(f"{m:<42} {r['calls']:>6} {r['retries']:>5} "
              f"{'OUI' if r['fell_back'] else 'non':>5} {r['coverage']:>5.2f} "
              f"{r['action_accuracy']:>5.2f} {r['invented']:>3} {r['seconds']:>5.1f}  "
              f"{','.join(r['errors']) or '—'}")
