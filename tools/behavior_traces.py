"""tools/behavior_traces.py — ancre le COMPORTEMENT dans les traces réelles.

L'automate du labo (.dot) dit *quels services* l'application utilise, *dans quel
ordre* et *avec quelles boucles* — mais pas avec quelles adresses. Les traces
(.csv) disent *quelles adresses* réalisent chaque service, *quel volume* et *à
quelle cadence*.

Ce module croise les deux pour produire un PROFIL COMPORTEMENTAL DÉPLOYABLE :

    service (du comportement)  →  adresses réelles + volume + périodicité

La périodicité est essentielle : elle donne la cadence NORMALE de l'application,
ce qui permet de calibrer la détection de beaconing sur son comportement réel
plutôt que sur un seuil arbitraire.

Format des traces : ts, app, src_ip, src_port, dst_ip, dst_port, proto, octets, paquets
"""
from __future__ import annotations

import csv
import ipaddress
import pathlib
import re
import statistics
from collections import defaultdict

from tools.behavior_profile import build_profile, port_matches

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_TRACES = _ROOT / "flowoid-traces-intern" / "traces_reseau" / "android_apps"


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def load_outbound(csv_path: str | pathlib.Path) -> list[dict]:
    """Charge les flux SORTANTS (appareil → extérieur). Ignore le trafic retour."""
    rows = []
    with open(csv_path, newline="") as fh:
        for r in csv.reader(fh):
            if len(r) < 9:
                continue
            try:
                ts, _app, sip, _sp, dip, dp, proto, nbytes, _pk = r[:9]
                if not _is_private(sip) or _is_private(dip):
                    continue                      # on ne garde que sortant → externe
                rows.append({"ts": float(ts), "ip": dip, "port": int(dp),
                             "proto": proto.strip().upper(), "bytes": int(nbytes)})
            except (ValueError, IndexError):
                continue
    return rows


# Mots sans valeur distinctive dans un nom d'organisation.
_STOP = {"inc", "llc", "ltd", "limited", "corp", "corporation", "company", "co", "com",
         "sa", "sas", "bv", "gmbh", "technologies", "technology", "cloud", "services",
         "service", "network", "networks", "coordination", "centre", "center", "the",
         "eu", "nl", "us", "de", "fr", "data", "hosting", "internet"}

# Rachats / renommages : le nom a changé depuis la capture des traces (2015).
_ALIAS = {"softlayer": "ibm"}


def _tokens(s: str) -> set[str]:
    """Marques distinctives d'un nom d'organisation (« Amazon.com, Inc. » → {amazon })."""
    toks = {t for t in re.split(r"[^a-z0-9]+", (s or "").lower())
            if len(t) > 2 and not t.isdigit() and t not in _STOP}
    return {_ALIAS.get(t, t) for t in toks}


def _org_match(label: str, org: str) -> bool:
    """L'organisation résolue correspond-elle à l'état du comportement ?

    On compare les MARQUES et non les chaînes exactes : les traces datent de 2015
    et la base de résolution donne la propriété actuelle. « Amazon Technologies »
    et « Amazon.com » désignent la même société ; « SoftLayer » est devenu « IBM ».
    Une comparaison littérale échouerait sur ces cas pourtant identiques.
    """
    a, b = _tokens(label), _tokens(org)
    if a & b:
        return True
    # Correspondance par PRÉFIXE de marque : les libellés de l'automate collent
    # parfois le suffixe (« NAZWAPL » pour « Nazwa.pl »). On accepte si une marque
    # d'au moins 5 lettres est le préfixe de l'autre (dans un sens ou l'autre).
    # Seuil à 5 pour éviter les faux appariements sur des marques courtes.
    for x in a:
        for y in b:
            if len(x) >= 5 and len(y) >= 5 and (x.startswith(y) or y.startswith(x)):
                return True
    return False


def _resolve_orgs(ips: set[str]) -> dict[str, str]:
    """adresse → organisation propriétaire (MaxMind, hors ligne). Tolérant aux échecs."""
    out: dict[str, str] = {}
    try:
        from enrichment.asn_resolver import AsnResolver
        r = AsnResolver()
        for ip in ips:
            try:
                res = r.resolve(ip)
                out[ip] = (getattr(res, "org", None) or getattr(res, "asn_org", None) or "")
            except Exception:
                out[ip] = ""
    except Exception:
        pass
    return out


SESSION_GAP = 3600.0        # au-delà d'1 h de silence : nouvelle session d'usage


def _periodicity(timestamps: list[float], session_gap: float = SESSION_GAP) -> dict:
    """Cadence NORMALE, mesurée À L'INTÉRIEUR des sessions d'usage.

    Les traces couvrent plusieurs semaines : les longs silences entre deux usages
    de l'application fausseraient complètement une moyenne globale. On ne retient
    donc que les intervalles intra-session (≤ 1 h) et on utilise la MÉDIANE,
    robuste aux valeurs extrêmes.

    cv (coefficient de variation) proche de 0 → trafic très RÉGULIER. C'est la
    signature d'un comportement automatique : c'est cette valeur qui permet de
    calibrer le beaconing sur ce que fait NORMALEMENT l'application.
    """
    ts = sorted(timestamps)
    gaps = [b - a for a, b in zip(ts, ts[1:]) if 0 < (b - a) <= session_gap]
    if len(gaps) < 2:
        return {"n": len(ts), "n_gaps": len(gaps), "median_interval_s": None,
                "cv": None, "regular": None}
    med = statistics.median(gaps)
    mean = statistics.mean(gaps)
    sd = statistics.stdev(gaps)
    cv = (sd / mean) if mean else None
    return {"n": len(ts), "n_gaps": len(gaps), "median_interval_s": round(med, 2),
            "cv": round(cv, 3) if cv is not None else None,
            "regular": (cv is not None and cv < 0.5)}


def enrich(app: str, rare_threshold: float = 0.01, orphan_watch: bool = True) -> dict:
    """Profil comportemental (.dot) ancré dans les traces réelles (.csv).

    orphan_watch : pour les automates par ORGANISATION, les IP observées dans les
    traces mais qu'aucune base ne rattache à une organisation connue (MaxMind vide,
    registre) sont regroupées dans un service « (non résolu) » SURVEILLÉ plutôt que
    perdues. Cela évite les faux positifs (le trafic légitime de l'app passe) SANS
    faire confiance à l'aveugle (le trafic non vérifié est inspecté par l'IDS)."""
    dot = _ROOT / "automates" / f"{app}.dot"
    prof = build_profile(dot, rare_threshold=rare_threshold)

    matches = sorted(_TRACES.glob(f"{app}*.csv"))
    if not matches:
        prof["traces"] = None
        return prof
    flows = load_outbound(matches[0])
    prof["traces_file"] = matches[0].name
    prof["n_flows"] = len(flows)

    # Certains automates du labo décrivent le comportement par ORGANISATION
    # (« Google LLC », « OVH »…) et non par port. L'outil ASN sert alors à
    # TRADUIRE l'organisation en adresses observées — pas à porter un jugement.
    org_states = [s for s in prof["services"] if s["spec"]["kind"] == "org"]
    ip_org: dict[str, str] = {}
    if org_states:
        ip_org = _resolve_orgs({f["ip"] for f in flows})

    # États « concrets » du comportement (port exact ou PLAGE de ports « 798/3 »)
    concrete = [s for s in prof["services"] if s["spec"]["kind"] in ("exact", "prefix")]
    for svc in prof["services"]:
        sp = svc["spec"]
        if sp["kind"] == "any":                    # l'état « * » : tout le reste
            if org_states:                          # « * » = organisation non listée
                known = [k["spec"]["org"] for k in org_states]
                sel = [f for f in flows
                       if not any(_org_match(o, ip_org.get(f["ip"], "")) for o in known)]
            else:
                sel = [f for f in flows
                       if not any(port_matches(k["spec"], f["port"]) for k in concrete)]
        elif sp["kind"] in ("exact", "prefix"):
            sel = [f for f in flows if port_matches(sp, f["port"])]
        else:                                       # état = organisation
            sel = [f for f in flows if _org_match(sp["org"], ip_org.get(f["ip"], ""))]
        per_ip: dict[str, dict] = defaultdict(lambda: {"flows": 0, "bytes": 0, "ts": []})
        for f in sel:
            d = per_ip[f["ip"]]
            d["flows"] += 1; d["bytes"] += f["bytes"]; d["ts"].append(f["ts"])
        svc["destinations"] = sorted(
            ({"ip": ip, "flows": d["flows"], "bytes": d["bytes"],
              "periodicity": _periodicity(d["ts"])} for ip, d in per_ip.items()),
            key=lambda x: -x["flows"])
        svc["protocols"] = sorted({f["proto"] for f in sel})
        svc["n_destinations"] = len(per_ip)
        svc["total_flows"] = len(sel)
        svc["total_bytes"] = sum(f["bytes"] for f in sel)
        svc["periodicity"] = _periodicity([f["ts"] for f in sel])

    # ── Hybride SÛR : IP observées mais NON rattachées à une organisation ──────
    # (MaxMind vide / registre) → service « (non résolu) » SURVEILLÉ, au lieu de
    # les perdre. Ce sont uniquement les IP PROPRES à cette app ; une déviation
    # vers une AUTRE IP inconnue reste bloquée par le default-deny. On ne l'ajoute
    # que pour les automates par organisation SANS état « * » (qui, lui, capte déjà
    # le reste).
    if (orphan_watch and org_states
            and not any(s["spec"]["kind"] == "any" for s in prof["services"])):
        attached = {d["ip"] for s in prof["services"] for d in s.get("destinations", [])}
        orphans = [f for f in flows if f["ip"] not in attached]
        if orphans:
            o_ip: dict[str, dict] = defaultdict(lambda: {"flows": 0, "bytes": 0, "ts": []})
            for f in orphans:
                d = o_ip[f["ip"]]
                d["flows"] += 1; d["bytes"] += f["bytes"]; d["ts"].append(f["ts"])
            dests = sorted(
                ({"ip": ip, "flows": d["flows"], "bytes": d["bytes"],
                  "periodicity": _periodicity(d["ts"])} for ip, d in o_ip.items()),
                key=lambda x: -x["flows"])
            prof["services"].append({
                "label": "(non résolu)", "spec": {"kind": "orphan", "label": "(non résolu)"},
                "orphan": True, "destinations": dests, "n_destinations": len(o_ip),
                "protocols": sorted({f["proto"] for f in orphans}),
                "total_flows": len(orphans), "total_bytes": sum(f["bytes"] for f in orphans),
                "periodicity": _periodicity([f["ts"] for f in orphans]),
            })
            prof["stats"]["n_services"] = len(prof["services"])
    return prof


def summary(prof: dict) -> str:
    lines = [f"Comportement de « {prof['app_name'].upper()} » ancré dans les traces "
             f"({prof.get('traces_file','—')}, {prof.get('n_flows',0)} flux sortants)", ""]
    for s in prof["services"]:
        if not s.get("destinations"):
            lines.append(f"  service {s['label']:<10} → aucun flux dans les traces")
            continue
        p = s["periodicity"]
        cad = (f"cadence médiane {p['median_interval_s']}s (cv={p['cv']}"
               f"{', RÉGULIER' if p.get('regular') else ''})") if p.get("median_interval_s") else "cadence n/d"
        lines.append(f"  service {s['label']:<10} | {s['n_destinations']:>3} IP | "
                     f"{s['total_flows']:>4} flux | {s['total_bytes']:>9} o | {cad}")
        for d in s["destinations"][:3]:
            lines.append(f"        └─ {d['ip']:<16} {d['flows']:>4} flux, {d['bytes']:>8} o")
    if prof["loops"]:
        lines += ["", "  Boucles NORMALES (calibrent le beaconing) : " + ", ".join(
            f"{l['service']} P={l['probability']:.3f}" for l in prof["loops"])]
    if prof["rare_transitions"]:
        lines.append("  Enchaînements RARES (à surveiller) : " + ", ".join(
            f"{t['from']}→{t['to']} P={t['probability']:.4f}" for t in prof["rare_transitions"]))
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    print(summary(enrich(app)))
