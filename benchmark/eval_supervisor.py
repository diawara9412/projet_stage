#!/usr/bin/env python3
"""
benchmark/eval_supervisor.py — Évaluation scientifique du SUPERVISEUR (archi 2,
agents LLM) sur les 7 automates enrichis (automates/*_enriched.json).

Pas de comparaison avec l'archi 1. Pour chaque app, lance le superviseur complet
UNE fois (deploy=False, sans réseau SDN) et collecte :

  RQ1 (correction)   : score validate_chain, nb conflits / orphelins / doublons.
  RQ2 (faux positifs): nb de destinations 'trusted' (reputation=trusted dans le
                       JSON enrichi) BLOQUÉES par la chaîne (attendu 0 ; listées si >0).
  RQ3 (couverture)   : DEUX métriques (honnêteté scientifique) —
                       (a) par IP : IP avec une règle dédiée / total ;
                       (b) par service : IP couverte si son ORG a un ALLOW (regroupement)
                           ou si elle a BLOCK/IDS dédié / total.
  RQ4 (fiabilité LLM): errors_before_correction par agent + total, nb d'appels LLM,
                       et SOURCE par agent ("llm" réussi vs "fallback" déterministe) —
                       un fallback signale que le LLM a échoué (JSON illisible, etc.).
  Méta               : type d'automate (ORG/PORT), nb transitions, catégories.

Sortie : tableau (7 lignes) + JSON (benchmark/eval_supervisor_results.json).

⚠️ CONSOMME DU QUOTA GROQ (~4-8 appels/app). Lancé MANUELLEMENT par l'utilisateur.
Garde-fou 401 : arrêt immédiat si erreur d'authentification.

Usage :
    python3 benchmark/eval_supervisor.py                 # 7 apps
    python3 benchmark/eval_supervisor.py --apps ratp,pokemongo
    python3 benchmark/eval_supervisor.py --yes           # sans confirmation
"""

import argparse
import json
import pathlib
import sys
import time

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import warnings
warnings.filterwarnings("ignore")

from benchmark.llm_counter import install, reset, snapshot, had_auth_error
install()  # compteur d'appels LLM sur ChatGroq.invoke (partagé)

from architectures.supervisor.graph_supervisor import build_supervisor_graph
from architectures.supervisor.supervisor_agent import SupervisorState

_ALL_APPS = ["disneyland", "dropbox", "faceswitch", "lequipe", "pokemongo", "ratp", "viber"]
_EST_CALLS_PER_APP = 6  # estimation moyenne (analyzer+fw+ids+ips + quelques retries)


def _get(obj, field):
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _f(obj, name, default=None):
    if obj is None:
        return default
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def _crit(sig):
    """dst_ip d'une IdsSignature (depuis match_criteria)."""
    mc = _f(sig, "match_criteria") or {}
    return mc.get("dst_ip") if isinstance(mc, dict) else None


def eval_app(app: str, suffix: str = "") -> dict:
    """Lance le superviseur sur un automate enrichi et collecte les métriques.

    ``suffix`` : "" pour la Condition A (automates/<app>_enriched.json), "_b" pour
    la Condition B (automates/<app>_enriched_b.json, enrichi par l'architecture).
    """
    enriched_path = _PROJECT_ROOT / "automates" / f"{app}_enriched{suffix}.json"
    enriched = json.loads(enriched_path.read_text(encoding="utf-8"))
    transitions = enriched.get("transitions", [])
    meta = enriched.get("metadata", {})

    # Destinations de l'automate + IPs 'trusted' (depuis le JSON enrichi)
    all_dst = {t["network_call"]["ip"] for t in transitions if t.get("network_call", {}).get("ip")}
    trusted_ips = {t["network_call"]["ip"] for t in transitions
                   if t.get("service", {}).get("reputation") == "trusted"
                   and t.get("network_call", {}).get("ip")}

    # ── Exécution du superviseur (1 run, sans déploiement) ──────────────────
    graph = build_supervisor_graph(deploy=False)
    state = SupervisorState(user_request=f"Éval superviseur {app}",
                            automate_path=str(enriched_path))
    reset()
    t0 = time.perf_counter()
    result = graph.invoke(state)
    dt = time.perf_counter() - t0
    llm_calls, _by = snapshot()

    chain = _get(result, "security_chain")
    report = _get(result, "validation_report")
    fw = _f(chain, "firewall_rules") or []
    ids = _f(chain, "ids_signatures") or []
    ips = _f(chain, "ips_actions") or []

    # ── RQ1 : correction ─────────────────────────────────────────────────────
    issues = _f(report, "issues") or []
    def _cat_count(c):
        return sum(1 for i in issues if _f(i, "category") == c)
    rq1 = {
        "score": _f(report, "quality_score"),
        "conflicts": _cat_count("conflict"),
        "orphans": _cat_count("orphan_reference"),
        "redundancies": _cat_count("redundancy"),
    }

    # ── RQ2 : faux positifs (trusted bloqués) ────────────────────────────────
    blocked_ips = [_f(r, "dst_ip") for r in fw if _f(r, "action") == "BLOCK" and _f(r, "dst_ip")]
    trusted_blocked = sorted(set(blocked_ips) & trusted_ips)
    rq2 = {"trusted_total": len(trusted_ips),
           "trusted_blocked": len(trusted_blocked),
           "trusted_blocked_ips": trusted_blocked}

    # ── RQ3 : couverture — DEUX métriques (honnêteté scientifique) ───────────
    # (a) par IP : l'IP a une règle DÉDIÉE qui la nomme (FW dst_ip ou IDS dst_ip).
    dedicated = {_f(r, "dst_ip") for r in fw if _f(r, "dst_ip")}
    dedicated |= {_crit(s) for s in ids if _crit(s)}
    covered_ip = dedicated & all_dst
    # (b) par service/org : une IP est couverte si son ORG a un ALLOW (le système
    #     regroupe les IP d'une org de confiance sous 1 ALLOW), OU si elle a une
    #     règle dédiée (BLOCK/IDS).
    ip_to_org = {t["network_call"]["ip"]: t.get("service", {}).get("asn_org")
                 for t in transitions if t.get("network_call", {}).get("ip")}
    allow_ips = {_f(r, "dst_ip") for r in fw
                 if _f(r, "action") in ("ALLOW", "ALLOW_AND_INSPECT") and _f(r, "dst_ip")}
    orgs_with_allow = {ip_to_org[ip] for ip in allow_ips if ip_to_org.get(ip)}
    covered_svc = {ip for ip in all_dst
                   if ip in dedicated or ip_to_org.get(ip) in orgs_with_allow}
    rq3 = {
        "total_dst": len(all_dst),
        "covered_ip": len(covered_ip),
        "ratio_ip": round(len(covered_ip) / len(all_dst), 3) if all_dst else None,
        "covered_svc": len(covered_svc),
        "ratio_svc": round(len(covered_svc) / len(all_dst), 3) if all_dst else None,
        # support pour recalcul OFFLINE ultérieur (sans relancer le LLM)
        "support": {
            "all_dst": sorted(all_dst),
            "dedicated": sorted(x for x in dedicated if x in all_dst),
            "allow_ips": sorted(allow_ips),
            "orgs_with_allow": sorted(o for o in orgs_with_allow if o),
        },
    }

    # ── RQ4 : fiabilité LLM (erreurs + SOURCE réelle par agent) ─────────────
    eb = {"firewall": 0, "ids": 0, "ips": 0}
    source = {"firewall": "?", "ids": "?", "ips": "?"}   # "llm" | "fallback" | "?"
    attempts_max = 0
    for ag, fld in (("firewall", "firewall_verification_report"),
                    ("ids", "ids_verification_report"),
                    ("ips", "ips_verification_report")):
        rep = _get(result, fld) or {}
        eb[ag] = rep.get("total_erreurs_llm_avant_correction", 0) or 0
        attempts_max = max(attempts_max, rep.get("attempts", 0) or 0)
        s = rep.get("source", "?")
        source[ag] = "fallback" if s == "fallback_deterministic" else ("llm" if s == "llm" else s)
    rq4 = {"errors_before": eb, "errors_before_total": sum(eb.values()),
           "attempts_max": attempts_max, "llm_calls": llm_calls, "source": source}

    return {
        "app": app,
        "meta": {"dot_label_type": meta.get("dot_label_type"),
                 "nb_transitions": len(transitions),
                 "category_counts": meta.get("category_counts", {})},
        "chain": {"fw": len(fw),
                  "block": sum(1 for r in fw if _f(r, "action") == "BLOCK"),
                  "allow": sum(1 for r in fw if _f(r, "action") in ("ALLOW", "ALLOW_AND_INSPECT")),
                  "ids": len(ids), "ips": len(ips)},
        "RQ1": rq1, "RQ2": rq2, "RQ3": rq3, "RQ4": rq4,
        "latency": round(dt, 1),
    }


def _print_table(rows: list[dict]) -> None:
    print("\n" + "=" * 118)
    print("  ÉVALUATION SUPERVISEUR (archi 2) — 7 automates enrichis")
    print("=" * 118)
    h = (f"  {'app':<11}{'type':<5}{'tr':>4}{'FW(B/A)':>9}{'IDS':>4}{'IPS':>4}"
         f"{'score':>6}{'cf':>3}{'or':>3}{'dup':>4}{'trustBlk':>9}{'couvIP':>8}{'couvSvc':>9}"
         f"{'errLLM':>7}{'att':>4}{'LLM':>4}{'src(F/I/P)':>11}{'s':>6}")
    print(h)
    print("  " + "-" * 133)
    for r in rows:
        c, q1, q2, q3, q4, m = r["chain"], r["RQ1"], r["RQ2"], r["RQ3"], r["RQ4"], r["meta"]
        fwba = f"{c['fw']}({c['block']}/{c['allow']})"
        cip = f"{q3['covered_ip']}/{q3['total_dst']}"
        csv = f"{q3['covered_svc']}/{q3['total_dst']}"
        s = q4["source"]
        # L=llm, F=fallback, ?=inconnu — ordre firewall/ids/ips
        src = "/".join({"llm": "L", "fallback": "F"}.get(s[ag], "?") for ag in ("firewall", "ids", "ips"))
        print(f"  {r['app']:<11}{str(m['dot_label_type']):<5}{m['nb_transitions']:>4}{fwba:>9}"
              f"{c['ids']:>4}{c['ips']:>4}{str(q1['score']):>6}{q1['conflicts']:>3}{q1['orphans']:>3}"
              f"{q1['redundancies']:>4}{q2['trusted_blocked']:>9}{cip:>8}{csv:>9}"
              f"{q4['errors_before_total']:>7}{q4['attempts_max']:>4}{q4['llm_calls']:>4}{src:>11}{r['latency']:>6}")
    print("=" * 118)
    print("  Légende : tr=transitions, FW(B/A)=firewall(BLOCK/ALLOW), cf=conflits, or=orphelins,")
    print("            dup=doublons, trustBlk=trusted bloqués (RQ2, attendu 0),")
    print("            couvIP=couverture par IP (1 règle dédiée/IP), couvSvc=couverture par service")
    print("            (une IP compte si son ORG a un ALLOW, ou si elle a BLOCK/IDS dédié),")
    print("            errLLM=erreurs avant correction (RQ4), att=attempts(max), LLM=appels Groq.")
    print("  NOTE : le système REGROUPE les IP d'une org de confiance sous 1 ALLOW unique")
    print("         (couvIP sous-estime donc la protection des orgs trusted), et il est en")
    print("         DEFAULT-ALLOW : une IP sans règle voit son trafic passer (pas de blocage implicite).")
    print("  src(F/I/P) = source par agent firewall/ids/ips : L=LLM réussi, F=FALLBACK déterministe")
    print("               (le LLM a échoué → repli). att/errLLM ne reflètent PAS le LLM si F.")

    # ── RQ4 : fiabilité LLM RÉELLE par agent (llm vs fallback) ───────────────
    print("\n  RQ4 — fiabilité LLM par agent (sur les apps évaluées) :")
    n = len(rows)
    for ag in ("firewall", "ids", "ips"):
        llm_ok = sum(1 for r in rows if r["RQ4"]["source"].get(ag) == "llm")
        fb = [r["app"] for r in rows if r["RQ4"]["source"].get(ag) == "fallback"]
        line = f"    {ag:<9}: LLM réussi {llm_ok}/{n}  |  fallback {len(fb)}/{n}"
        if fb:
            line += f"  → {fb}"
        print(line)
    # RQ2 : alertes faux positifs
    viol = [r for r in rows if r["RQ2"]["trusted_blocked"] > 0]
    if viol:
        print("\n  ⚠️ FAUX POSITIFS (RQ2) — destinations trusted BLOQUÉES :")
        for r in viol:
            print(f"     {r['app']} : {r['RQ2']['trusted_blocked_ips']}")
    else:
        print("\n  ✅ RQ2 : aucune destination trusted bloquée sur les apps évaluées.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Évaluation du superviseur sur automates enrichis")
    parser.add_argument("--apps", default=None, help="sous-ensemble (ex: ratp,pokemongo)")
    parser.add_argument("--variant", choices=["a", "b"], default="a",
                        help="a = enriched.json (pipeline) ; b = enriched_b.json (architecture Analyzer-B)")
    parser.add_argument("--yes", action="store_true", help="ne pas demander confirmation")
    args = parser.parse_args()

    suffix = "_b" if args.variant == "b" else ""

    import logging
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    names = [a.strip() for a in args.apps.split(",")] if args.apps else list(_ALL_APPS)
    apps = []
    for n in names:
        if (_PROJECT_ROOT / "automates" / f"{n}_enriched{suffix}.json").exists():
            apps.append(n)
        else:
            print(f"⚠️ ignoré (introuvable) : automates/{n}_enriched{suffix}.json")
    if not apps:
        print("❌ aucune app valide."); return 1

    est = len(apps) * _EST_CALLS_PER_APP
    print("=" * 70)
    src_label = "B (architecture / Analyzer-B)" if suffix else "A (pipeline enrichment/)"
    print(f"  ÉVALUATION SUPERVISEUR — Condition {src_label}")
    print(f"  fichiers : automates/<app>_enriched{suffix}.json")
    print(f"  apps : {apps}")
    print(f"  appels Groq estimés ≈ {est} (~{_EST_CALLS_PER_APP}/app, retries inclus)")
    print("=" * 70)
    if not args.yes:
        if input("  Lancer ? [o/N] ").strip().lower() not in ("o", "oui", "y", "yes"):
            print("  Annulé."); return 0

    rows = []
    for app in apps:
        print(f"  … {app}")
        try:
            rows.append(eval_app(app, suffix=suffix))
        except Exception as exc:
            logging.error("  %s ÉCHOUÉ : %s", app, exc)
        if had_auth_error():
            print("\n  ⛔ 401 / quota Groq épuisé — ARRÊT immédiat.")
            break

    if rows:
        _print_table(rows)
    out = _PROJECT_ROOT / "benchmark" / f"eval_supervisor_results{suffix}.json"
    out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Résultats → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
