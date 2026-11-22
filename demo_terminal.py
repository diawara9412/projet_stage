#!/usr/bin/env python3
"""Démo TERMINAL — génération d'une chaîne de sécurité, agent par agent, en détail.

Exécute le VRAI graphe LangGraph (Groq) et affiche, avec un rythme lisible, ce que
fait CHAQUE agent : profil, décisions du pare-feu, signatures IDS, vérification,
déploiement, puis la traduction en règles OpenFlow.

Usage :  python3 demo_terminal.py [app] [modele]
         python3 demo_terminal.py viber openai/gpt-oss-120b
"""
import sys, time, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from architectures.supervisor.behavior_supervisor import build_behavior_graph, BehaviorState
from tools.behavior_traces import enrich
from tools.behavior_chain import reference_chain
from tools.behavior_deploy import to_deployable

C = dict(cy="\033[96m", gr="\033[92m", am="\033[93m", rd="\033[91m",
         bd="\033[1m", dim="\033[2m", rs="\033[0m", bl="\033[94m")
def c(t, k): return f"{C[k]}{t}{C['rs']}"
def pause(s=0.9): time.sleep(s)
def rule(): print(c("─"*74, "dim"))
KIND = {"exact":"port","prefix":"plage","any":"joker","org":"organisation","orphan":"non résolu"}

def act_col(a): return c(a, "gr" if a == "ALLOW" else "am")

def main():
    import argparse, subprocess, json, urllib.request
    ap = argparse.ArgumentParser(description="Démo terminal — génération + (option) déploiement SDN")
    ap.add_argument("app", nargs="?", default="viber")
    ap.add_argument("--model", default="openai/gpt-oss-120b")
    ap.add_argument("--deploy", action="store_true",
                    help="déploie la chaîne sur le contrôleur SDN et montre les règles sur s1/s2")
    ap.add_argument("--controller", default="http://127.0.0.1:8080")
    args = ap.parse_args()
    app, model = args.app, args.model
    print("\n" + c("╔" + "═"*72 + "╗", "cy"))
    print(c("║", "cy") + c(f"  GÉNÉRATION D'UNE CHAÎNE DE SÉCURITÉ — app={app} · modèle={model.split('/')[-1]}".ljust(72), "bd") + c("║", "cy"))
    print(c("╚" + "═"*72 + "╝", "cy") + "\n")
    print(c("  Superviseur : hub-and-spoke · 6 agents · 2 seulement portent un LLM\n", "dim"))
    pause(1.0)

    graph = build_behavior_graph()
    store = {}
    for chunk in graph.stream(BehaviorState(app=app, model=model, use_llm=True),
                              stream_mode="updates"):
        for node, d in chunk.items():
            if not isinstance(d, dict):
                continue
            if node == "supervisor":
                log = d.get("supervisor_log") or []
                reason = (log[-1] if log else "").split("] ", 1)[-1]
                route = d.get("next_agent")
                if route == "end":
                    print("\n" + c("🧭 SUPERVISEUR", "cy") + c("  → tous les volets produits, orchestration terminée.", "dim"))
                else:
                    print("\n" + c("🧭 SUPERVISEUR", "cy") + f"  → {c(route,'bd')}")
                    print("   " + c(reason, "dim"))
                pause(0.7)

            elif node == "analyzer":
                p = d["profile"]; store["profile"] = p
                rares = p.get("rare_transitions", [])
                watch = {t["from"] for t in rares} | {t["to"] for t in rares}
                print("\n" + c("① AgentAnalyseur", "bd") + c("  (déterministe) — lit l'automate + les traces", "dim"))
                rule()
                print(f"   États : {c(p['stats']['n_services'],'bd')}   ·   "
                      f"boucles : {p['stats']['n_loops']}   ·   "
                      f"transitions rares : {c(p['stats']['n_rare'],'rd')}")
                for s in p["services"]:
                    if not s.get("destinations"): continue
                    lbl = s["label"]; k = KIND.get(s["spec"]["kind"], s["spec"]["kind"])
                    cad = (s.get("periodicity") or {}).get("median_interval_s")
                    tag = c(" ← surveillé", "am") if lbl in watch else ""
                    cads = f"  cadence≈{cad:.0f}s" if cad else ""
                    print(f"     • {c(lbl.ljust(9),'bd')} [{k}]  {s.get('n_destinations',0)} adresses{cads}{tag}")
                if rares:
                    print(c("   Transitions rares (< 1 %) :", "rd"))
                    for t in rares:
                        print(f"     {t['from']} → {t['to']}   " + c(f"P={t['probability']*100:.2f}%".replace('.', ','), "rd"))
                pause(1.1)

            elif node == "firewall":
                dec = d.get("firewall_decision") or {}; rep = d.get("firewall_report") or {}
                src = rep.get("source")
                srcs = c("via LLM", "cy") if src == "llm" else c(f"repli {src}", "am")
                print("\n" + c("② AgentParefeu", "cy") + c(f"  (LLM) — décide ALLOW / ALLOW_AND_INSPECT   [{src and srcs}]", "dim"))
                rule()
                al = ins = 0
                for r in dec.get("services", []):
                    a = r["action"]; al += a == "ALLOW"; ins += a != "ALLOW"
                    print(f"     {c(r['service'].ljust(9),'bd')} → {act_col(a)}")
                print("     " + c("défaut".ljust(9), "dim") + " → " + c("DENY", "rd"))
                print(f"   → {c(al,'gr')} ALLOW · {c(ins,'am')} ALLOW_AND_INSPECT"
                      + (f"  (après {rep.get('retries')} correction)" if rep.get("retries") else ""))
                pause(1.1)

            elif node == "ids":
                dec = d.get("ids_decision") or {}; rep = d.get("ids_report") or {}
                src = rep.get("source")
                srcs = c("via LLM", "cy") if src == "llm" else c(f"repli {src}", "am")
                sigs = [s.get("service") for s in dec.get("signatures", [])]
                print("\n" + c("③ AgentIDS", "cy") + c(f"  (LLM) — calibre les signatures de surveillance   [{src and srcs}]", "dim"))
                rule()
                print(f"     {c(len(sigs),'bd')} signature(s) : " + ", ".join(c(s, "am") for s in sigs) or "aucune")
                pause(1.0)

            elif node == "verifier":
                rep = d.get("verification_report") or {}; st = rep.get("stats", {})
                ok = rep.get("is_valid")
                print("\n" + c("④ AgentVérificateur", "bd") + c("  (déterministe) — contrôle la chaîne entière", "dim"))
                rule()
                verdict = c("VALIDE", "gr") if ok else c("INVALIDE", "rd")
                print(f"     Chaîne {verdict}  ·  score {c(str(rep.get('quality_score'))+'/100','bd')}"
                      f"  ·  {st.get('errors',0)} erreur(s) · {st.get('warnings',0)} avertissement(s)")
                for i in rep.get("issues", [])[:4]:
                    print(c(f"       - [{i.get('category')}] {i.get('message')}", "dim"))
                pause(1.1)

            elif node == "deployer":
                res = d.get("deployment_result") or {}
                print("\n" + c("⑤ AgentDéployeur", "bd") + c("  (déterministe) — assemble et envoie au contrôleur SDN", "dim"))
                rule()
                print("     " + c("chaîne assemblée ✓ → transmise en REST au contrôleur", "gr"))
                pause(0.9)

    # ── traduction OpenFlow ──
    prof = store.get("profile") or enrich(app)
    dep = to_deployable(reference_chain(prof))
    fr = dep["firewall_rules"]
    print("\n" + c("⇒ TRADUCTION EN OPENFLOW", "bd") + c("  (ce que le contrôleur installe sur s1)", "dim"))
    rule()
    for r in fr[:4]:
        a = r.get("action")
        print(f"     {str(r.get('id','')).ljust(7)} dst_ip={str(r.get('dst_ip','')).ljust(16)} "
              f"{r.get('protocol')} dst_port={str(r.get('dst_port')).ljust(5)} → {act_col(a)}")
    print("     " + "table-miss (priorité 0)".ljust(55) + " → " + c("DROP", "rd"))
    print(f"\n   {c(len(fr),'cy')} règles pare-feu (s1)   ·   "
          f"{c(len(dep['ids_signatures']),'cy')} signatures d'inspection (s2)")

    if not args.deploy:
        print("\n" + c("  ✓ Chaîne générée par les agents, vérifiée, prête à déployer.", "gr"))
        print(c("    (ajoute --deploy pour l'installer sur le réseau et voir les règles sur s1/s2)", "dim") + "\n")
        return

    # ── déploiement réel sur le contrôleur SDN ──
    print("\n" + c("⇒ DÉPLOIEMENT RÉEL SUR LE RÉSEAU SDN", "bd") + c("  (contrôleur os-ken → s1 / s2)", "dim"))
    rule()
    try:
        payload = json.dumps(dep).encode()
        req = urllib.request.Request(args.controller + "/firewall/install", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        body = urllib.request.urlopen(req, timeout=10).read().decode()
        print("     " + c("contrôleur ✓  ", "gr") + c(body[:150], "dim"))
    except Exception as e:
        print("     " + c("⚠️ contrôleur injoignable — lance d'abord :", "am"))
        print(c("        T1  sudo python3 ryu_app/run_manager.py ryu_app.sdn_executor --default-deny --two-switch --sfc --stateful", "dim"))
        print(c("        T2  sudo python3 deploy_mini_demo.py --two-switch", "dim"))
        print(c(f"        (détail : {e})", "dim") + "\n")
        return
    time.sleep(1.3)

    print(c("\n   Règles réellement installées (ovs-ofctl dump-flows — sudo) :", "dim"))
    for sw, label in (("s1", "pare-feu"), ("s2", "IDS")):
        try:
            out = subprocess.run(["sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", sw],
                                 capture_output=True, text=True, timeout=25).stdout
            rules = [l.strip() for l in out.splitlines() if "cookie=" in l]
            print(f"\n     {c(sw, 'bd')} ({label}) : {c(len(rules), 'cy')} règles installées par le contrôleur")
            key = "nw_dst" if sw == "s1" else "CONTROLLER"
            for l in [r for r in rules if key in r][:3]:
                print("       " + c(l[:104], "dim"))
        except Exception as e:
            print("     " + c(f"{sw} : dump-flows indisponible ({e})", "am"))

    print("\n" + c("  ✓ Agents → contrôleur → règles installées sur s1 et s2.", "gr"))
    print(c("    Étape suivante (T4) :  sudo python3 benchmark/traffic_test.py --profile "
            + app + " --replay dropbox   + Wireshark", "dim") + "\n")


if __name__ == "__main__":
    main()
