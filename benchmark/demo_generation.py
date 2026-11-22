"""Affiche le PROCESSUS COMPLET de génération d'une chaîne, étape par étape :
Analyseur (déterministe) → Firewall (LLM) → IDS (LLM) → Vérificateur (déterministe).
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools.behavior_traces import enrich
from tools.behavior_chain import brief
from agents.chain_checker import check_chain, format_report
from benchmark.eval_behavior_pipeline import (
    _run_agent, FW_PROMPT, IDS_PROMPT, _fw_check, _ids_check, _assemble, _key)

BAR = "=" * 78


def demo(app, model="openai/gpt-oss-120b"):
    from langchain_groq import ChatGroq
    print(f"\n{BAR}\n  GENERATION DE LA CHAINE — application « {app} »  (modele : {model})\n{BAR}")
    prof = enrich(app)
    rare = {t["from"] for t in prof["rare_transitions"]} | {t["to"] for t in prof["rare_transitions"]}

    print("\n-- (1) ANALYSEUR (deterministe) : lit le comportement ----------------------")
    s = prof["stats"]
    print(f"   {s['n_services']} services · {s['n_transitions']} enchainements · "
          f"{s['n_loops']} boucles · {s['n_rare']} rares")
    for sv in prof["services"]:
        if not sv.get("destinations"):
            continue
        p = sv.get("periodicity", {}) or {}
        cad = f" · cadence {p['median_interval_s']}s" if p.get("median_interval_s") else ""
        tag = "  <- enchainement RARE" if sv["label"] in rare else ""
        print(f"      service {sv['label']:<10} {sv['n_destinations']:>3} adresses{cad}{tag}")

    llm = ChatGroq(model=model, api_key=_key(), temperature=0, request_timeout=45, max_retries=1)

    print("\n-- (2) FIREWALL (LLM) : decide quoi autoriser / surveiller -----------------")
    fw_dec, fwm = _run_agent(llm, FW_PROMPT.format(brief=brief(prof)), lambda d: _fw_check(d, prof))
    print(f"   {fwm['calls']} appel(s), {fwm['retries']} reprise(s), "
          f"{fwm['in_tok']+fwm['out_tok']} tokens   |   default = {(fw_dec or {}).get('default_action')}")
    if fwm["errors"]:
        print(f"   erreurs corrigees : {', '.join(fwm['errors'])}")
    for d in (fw_dec or {}).get("services", []):
        print(f"      {str(d.get('action')):<18} service {d.get('service')}")

    watch = [d["service"] for d in (fw_dec or {}).get("services", [])
             if str(d.get("action", "")).upper() == "ALLOW_AND_INSPECT"]
    loops = ", ".join(
        f"{l['service']}:{(next((x for x in prof['services'] if x['label']==l['service']),{}).get('periodicity',{}) or {}).get('median_interval_s')}"
        for l in prof["loops"])

    print("\n-- (3) IDS (LLM) : decide quoi surveiller (signatures beaconing) -----------")
    ids_dec, idsm = _run_agent(llm, IDS_PROMPT.format(watch=watch or "(aucun)", loops=loops or "(aucune)"),
                               lambda d: _ids_check(d, watch))
    print(f"   {idsm['calls']} appel(s), {idsm['retries']} reprise(s), "
          f"{idsm['in_tok']+idsm['out_tok']} tokens")
    if idsm["errors"]:
        print(f"   erreurs corrigees : {', '.join(idsm['errors'])}")
    for s2 in (ids_dec or {}).get("signatures", []):
        print(f"      signature IDS -> service {s2.get('service')}")

    chain = _assemble(fw_dec, ids_dec, prof)
    print("\n-- CHAINE ASSEMBLEE (code) ------------------------------------------------")
    print(f"   default_action = {chain['default_action']}")
    for r in chain["firewall_rules"]:
        ips = f"{len(r['destinations'])} IP" if r["destinations"] else "-"
        print(f"      {r['action']:<18} {r['service']:<10} {r['protocol']:<4} ({ips})")

    print("\n-- (4) VERIFICATEUR (deterministe) : controle la chaine entiere ------------")
    rep = check_chain(chain, prof)
    print("   " + format_report(rep).replace("\n", "\n   "))
    return chain, prof


if __name__ == "__main__":
    apps = sys.argv[1].split(",") if len(sys.argv) > 1 else ["viber", "lequipe"]
    for a in apps:
        demo(a)
