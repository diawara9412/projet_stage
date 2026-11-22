"""benchmark/trace_generation.py — TRACE COMPLÈTE de la génération d'une chaîne.

Affiche, pour chaque agent et chaque tentative :
  · la SORTIE BRUTE du modèle,
  · ce que le VÉRIFICATEUR a détecté (message exact),
  · le RETOUR envoyé au modèle,
  · et pourquoi il y a eu un appel supplémentaire.
"""
import sys, pathlib, json, textwrap
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools.behavior_traces import enrich
from tools.behavior_chain import brief
from agents.chain_checker import check_chain, format_report
from benchmark.eval_behavior_pipeline import (
    FW_PROMPT, IDS_PROMPT, _fw_check, _ids_check, _assemble, _parse, _key, _usage)

W = 88


def show(txt, ind="      "):
    for line in textwrap.wrap(txt, W - len(ind)) or [""]:
        print(ind + line)


def verbose_agent(llm, name, prompt, checker, max_attempts=3):
    print(f"\n{'─'*W}\n AGENT {name}\n{'─'*W}")
    feedback, dec, calls, retries, toks = "", None, 0, 0, 0
    for attempt in range(1, max_attempts + 1):
        calls += 1
        print(f"\n  ▸ APPEL {attempt}" + ("  (relance après correction)" if attempt > 1 else ""))
        resp = llm.invoke(prompt + ("\n\nCorrige ces erreurs :\n" + feedback if feedback else ""))
        it, ot = _usage(resp); toks += it + ot
        raw = resp.content.strip()
        print(f"    tokens : {it} entrée / {ot} sortie")
        print("    SORTIE BRUTE DU MODÈLE :")
        show(raw[:700] + ("…" if len(raw) > 700 else ""), "      ")
        d = _parse(raw)
        if not d:
            print("    ✗ VÉRIFICATEUR : sortie non parsable (JSON invalide)")
            retries += 1; feedback = "Ta réponse n'était pas un JSON valide."
            print("    → renvoyé au modèle"); continue
        errs = checker(d)
        if not errs:
            print(f"    ✓ VÉRIFICATEUR : aucune erreur — sortie ACCEPTÉE")
            dec = d; break
        print(f"    ✗ VÉRIFICATEUR : {len(errs)} erreur(s) détectée(s) :")
        for cat, msg in errs:
            print(f"        [{cat}] {msg}")
        feedback = "\n".join("- " + m for _, m in errs)
        retries += 1; dec = d
        print("    → RETOUR envoyé au modèle :")
        show(feedback.replace("\n", " | "), "        ")
    print(f"\n  ⇒ bilan {name} : {calls} appel(s), {retries} reprise(s), {toks} tokens")
    return dec, calls, retries, toks


def trace(app, model):
    from langchain_groq import ChatGroq
    print("=" * W)
    print(f" TRACE COMPLÈTE — application « {app} »   modèle « {model} »")
    print("=" * W)
    prof = enrich(app)
    rare = {t["from"] for t in prof["rare_transitions"]} | {t["to"] for t in prof["rare_transitions"]}
    print("\n ① ANALYSEUR (déterministe) — comportement extrait :")
    for s in prof["services"]:
        if not s.get("destinations"): continue
        tag = "  ← RARE (doit être surveillé)" if s["label"] in rare else ""
        print(f"      service {s['label']:<10} {s['n_destinations']:>3} adresses{tag}")
    print(f"      → attendu : {len(rare & {s['label'] for s in prof['services'] if s.get('destinations')})} "
          f"service(s) à surveiller, le reste simplement autorisé")

    llm = ChatGroq(model=model, api_key=_key(), temperature=0, request_timeout=45, max_retries=1)
    fw, c1, r1, t1 = verbose_agent(llm, "FIREWALL (décide autoriser / surveiller)",
                                   FW_PROMPT.format(brief=brief(prof)), lambda d: _fw_check(d, prof))
    watch = [d["service"] for d in (fw or {}).get("services", [])
             if str(d.get("action", "")).upper() == "ALLOW_AND_INSPECT"]
    loops = ", ".join(f"{l['service']}:{(next((x for x in prof['services'] if x['label']==l['service']),{}).get('periodicity',{}) or {}).get('median_interval_s')}"
                      for l in prof["loops"])
    ids, c2, r2, t2 = verbose_agent(llm, "IDS (décide quoi surveiller)",
                                    IDS_PROMPT.format(watch=watch or "(aucun)", loops=loops or "(aucune)"),
                                    lambda d: _ids_check(d, watch))

    chain = _assemble(fw, ids, prof)
    print(f"\n{'─'*W}\n CHAÎNE ASSEMBLÉE + VÉRIFICATION FINALE\n{'─'*W}")
    print(f"   default_action = {chain['default_action']}")
    for r in chain["firewall_rules"]:
        print(f"      {r['action']:<18} {r['service']:<10} {r['protocol']:<4} ({len(r['destinations'])} IP)")
    rep = check_chain(chain, prof)
    print("   " + format_report(rep).replace("\n", "\n   "))
    print(f"\n{'='*W}")
    print(f" BILAN : {c1+c2} appels au total  =  FIREWALL {c1} + IDS {c2}   "
          f"({r1+r2} reprise(s), {t1+t2} tokens)")
    if c1 > 1: print(f"   → l'appel supplémentaire vient du FIREWALL ({r1} correction(s))")
    if c2 > 1: print(f"   → l'appel supplémentaire vient de l'IDS ({r2} correction(s))")
    print("=" * W)


if __name__ == "__main__":
    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    model = sys.argv[2] if len(sys.argv) > 2 else "llama-3.3-70b-versatile"
    trace(app, model)
