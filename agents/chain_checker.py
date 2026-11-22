"""agents/chain_checker.py — VÉRIFICATEUR de la chaîne ENTIÈRE (déterministe).

Dernier rempart avant le déploiement. Contrairement aux outils de vérification
par agent (qui contrôlent CHAQUE sortie isolément), ce vérificateur contrôle la
chaîne ASSEMBLÉE, par rapport au COMPORTEMENT dont elle est issue.

Il est volontairement DÉTERMINISTE (aucun LLM) : une vérification à laquelle on
ne peut pas faire confiance ne sert à rien. C'est la garantie finale — au même
titre que le Superviseur et le Déployeur, elle relève du contrôle, pas du
jugement.

Six contrôles, adaptés au modèle liste blanche comportemental :
  1. couverture          — tout service OBSERVÉ du comportement est dans la chaîne
  2. service inventé     — la chaîne n'autorise aucun service ABSENT du comportement
  3. surveillé ⇒ signature — tout ALLOW_AND_INSPECT possède une signature IDS
  4. boucle ⇒ seuil      — toute boucle à cadence mesurée a un seuil de beaconing
  5. default-deny        — la règle « refuser tout le reste » est présente
  6. déployable          — chaque règle a une cible concrète (port/plage + adresses)

Entrées :
  chain   = sortie de behavior_chain.reference_chain (ou d'un agent LLM, même forme)
  profile = sortie de behavior_traces.enrich (le comportement de référence)
"""
from __future__ import annotations

ERROR, WARNING, INFO = "ERROR", "WARNING", "INFO"


def _svc(profile: dict, label: str) -> dict | None:
    return next((s for s in profile["services"] if s["label"] == label), None)


def check_chain(chain: dict, profile: dict) -> dict:
    """Contrôle la chaîne assemblée contre le comportement. Retourne un rapport."""
    issues: list[dict] = []

    def add(sev, cat, msg, ref=None, fix=None):
        issues.append({"severity": sev, "category": cat, "message": msg,
                       "service": ref, "suggested_fix": fix})

    fw = chain.get("firewall_rules", [])
    ids = chain.get("ids_signatures", [])

    # Ensembles utiles
    observed = {s["label"] for s in profile["services"] if s.get("destinations")}
    behavior = {s["label"] for s in profile["services"]}
    rule_services = {r["service"] for r in fw}
    inspect_services = {r["service"] for r in fw if r["action"] == "ALLOW_AND_INSPECT"}
    sig_services = {s["service"] for s in ids}
    rare = {t["from"] for t in profile["rare_transitions"]} | \
           {t["to"] for t in profile["rare_transitions"]}
    loops_cadence = {l["service"] for l in profile["loops"]
                     if (_svc(profile, l["service"]) or {}).get("periodicity", {}).get("median_interval_s")}

    # 1. Couverture — aucun service observé oublié
    for lbl in sorted(observed - rule_services):
        add(ERROR, "coverage", f"service « {lbl} » observé dans le comportement mais ABSENT de la chaîne",
            lbl, "ajouter une règle ALLOW pour ce service")

    # 2. Service inventé — rien qui ne soit dans le comportement
    for lbl in sorted(rule_services - behavior):
        add(ERROR, "invented_service", f"la chaîne autorise « {lbl} », ABSENT du comportement observé",
            lbl, "retirer cette règle (hallucination)")

    # 3. Conflit — un même service avec des actions contradictoires
    from collections import Counter
    acts: dict[str, set] = {}
    for r in fw:
        acts.setdefault(r["service"], set()).add(r["action"])
    for lbl, a in acts.items():
        if "ALLOW" in a and "ALLOW_AND_INSPECT" in a:
            add(ERROR, "conflict", f"service « {lbl} » à la fois ALLOW et ALLOW_AND_INSPECT", lbl)

    # 4. Surveillé ⇒ signature
    for lbl in sorted(inspect_services - sig_services):
        add(ERROR, "inspect_without_signature",
            f"service « {lbl} » sous surveillance (ALLOW_AND_INSPECT) mais SANS signature IDS",
            lbl, "ajouter une signature IDS pour ce service")

    # …et réciproquement : les enchaînements rares doivent être surveillés
    for lbl in sorted((rare & observed) - inspect_services):
        add(WARNING, "unwatched_rare",
            f"service « {lbl} » impliqué dans un enchaînement rare mais NON surveillé", lbl,
            "passer ce service en ALLOW_AND_INSPECT")

    # 5. Boucle ⇒ seuil de beaconing
    sig_by_service = {s["service"]: s for s in ids}
    for lbl in sorted(loops_cadence & observed):
        sig = sig_by_service.get(lbl)
        if not sig or sig.get("beaconing_threshold_s") in (None, 0):
            add(WARNING, "loop_without_threshold",
                f"boucle normale sur « {lbl} » sans seuil de beaconing calibré", lbl,
                "renseigner beaconing_threshold_s depuis la cadence mesurée")

    # 6. Default-deny présent
    if str(chain.get("default_action", "")).upper() != "DENY":
        add(ERROR, "missing_default_deny",
            "la politique par défaut n'est pas DENY (le modèle liste blanche l'exige)",
            None, "définir default_action = DENY")

    # 7. Déployable — chaque règle a une cible concrète
    for r in fw:
        spec = r.get("spec", {})
        has_port = spec.get("kind") in ("exact", "prefix")
        has_ips = bool(r.get("destinations"))
        if not has_port and not has_ips:
            add(WARNING, "not_deployable",
                f"règle « {r['service']} » sans port ni adresse résolue → non déployable", r["service"],
                "résoudre l'organisation en adresses, ou retirer la règle")

    # 8. Signature orpheline — signature pour un service non autorisé
    for lbl in sorted(sig_services - rule_services):
        add(WARNING, "orphan_signature",
            f"signature IDS pour « {lbl} » qui n'a aucune règle de pare-feu", lbl)

    n_err = sum(1 for i in issues if i["severity"] == ERROR)
    n_warn = sum(1 for i in issues if i["severity"] == WARNING)
    score = max(0, 100 - 25 * n_err - 8 * n_warn)
    return {
        "app": chain.get("app"),
        "is_valid": n_err == 0,
        "quality_score": score,
        "issues": issues,
        "stats": {"errors": n_err, "warnings": n_warn,
                  "services_observed": len(observed), "rules": len(fw),
                  "signatures": len(ids), "coverage_ok": not (observed - rule_services)},
    }


def format_report(rep: dict) -> str:
    ico = {ERROR: "✗", WARNING: "!", INFO: "·"}
    head = (f"Vérification chaîne « {rep['app']} » — "
            f"{'VALIDE' if rep['is_valid'] else 'INVALIDE'} · score {rep['quality_score']}/100 "
            f"({rep['stats']['errors']} erreurs, {rep['stats']['warnings']} avertissements)")
    lines = [head, "-" * len(head)]
    if not rep["issues"]:
        lines.append("  aucun problème — chaîne cohérente avec le comportement.")
    for i in rep["issues"]:
        lines.append(f"  {ico[i['severity']]} [{i['category']}] {i['message']}")
        if i.get("suggested_fix"):
            lines.append(f"       → {i['suggested_fix']}")
    return "\n".join(lines)


if __name__ == "__main__":
    import copy, sys
    from tools.behavior_traces import enrich
    from tools.behavior_chain import reference_chain

    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    prof = enrich(app)
    ref = reference_chain(prof)

    print("### 1) Chaîne de RÉFÉRENCE (attendue correcte)\n")
    print(format_report(check_chain(ref, prof)))

    print("\n\n### 2) Chaîne CASSÉE volontairement (le vérificateur doit tout attraper)\n")
    bad = copy.deepcopy(ref)
    bad["default_action"] = "ALLOW"                       # (5) default-deny cassé
    if bad["firewall_rules"]:
        bad["firewall_rules"].pop(0)                       # (1) service oublié
    bad["firewall_rules"].append({                         # (2) service inventé
        "service": "31337", "spec": {"kind": "exact", "port": 31337},
        "protocol": "TCP", "action": "ALLOW", "destinations": ["6.6.6.6"]})
    bad["ids_signatures"] = []                             # (3,4) plus aucune signature
    print(format_report(check_chain(bad, prof)))
