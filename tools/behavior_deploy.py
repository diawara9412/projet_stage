"""tools/behavior_deploy.py — PONT : chaîne comportementale → chaîne DÉPLOYABLE.

La chaîne produite par les agents raisonne par SERVICE (un port, une plage, un
joker). Le contrôleur SDN, lui, installe des règles OpenFlow concrètes, qui se
matchent sur une adresse et un port. Ce module fait la traduction :

    service (avec ses adresses observées)  →  une règle par adresse

  · service à port exact  → règle (dst_ip, dst_port)
  · plage de ports / joker → règle (dst_ip) sans port  (toute la destination)
  · service ALLOW_AND_INSPECT → en plus, une signature IDS par adresse, dont le
    commentaire porte la CADENCE NORMALE mesurée (seuil de beaconing).
"""
from __future__ import annotations
import json


def _lan_base_rules() -> list[dict]:
    """Règles LAN de base (priorité 50) — INDISPENSABLES pour que le trafic circule.

    Sans elles, en default-deny, la table-miss droppe l'ARP → l'hôte ne résout pas
    sa passerelle → RIEN ne passe (ni le trafic autorisé). Les anciennes chaînes les
    recevaient via tools/deterministic_repairs.add_missing_lan ; la chaîne
    comportementale doit donc les inclure aussi. Cf. sdn_executor (LAN/ARP/ICMP à 50)."""
    return [
        {"id": "FW-LAN-ARP", "action": "ALLOW", "dst_ip": None, "protocol": "ARP",
         "dst_port": None, "priority": 50},
        {"id": "FW-LAN-IPV4", "action": "ALLOW", "dst_ip": "10.0.0.0/24", "protocol": "any",
         "dst_port": None, "priority": 50},
        {"id": "FW-LAN-ICMP", "action": "ALLOW", "dst_ip": "10.0.0.0/24", "protocol": "ICMP",
         "dst_port": None, "priority": 50},
    ]


def to_deployable(chain: dict, max_ip: int | None = None) -> dict:
    """Convertit la chaîne comportementale au format attendu par /firewall/install."""
    fw, ids = list(_lan_base_rules()), []
    thr = {s["service"]: s.get("beaconing_threshold_s") for s in chain.get("ids_signatures", [])}

    for r in chain["firewall_rules"]:
        spec = r.get("spec", {}) or {}
        port = spec.get("port") if spec.get("kind") == "exact" else None   # plage/joker → tout port
        dests = r.get("destinations", [])
        if max_ip:
            dests = dests[:max_ip]
        for ip in dests:
            fw.append({"id": f"FW-{len(fw)+1:03d}", "action": r["action"], "dst_ip": ip,
                       "protocol": r["protocol"], "dst_port": port, "priority": 100})
            if r["action"] == "ALLOW_AND_INSPECT":
                ids.append({"id": f"IDS-{len(ids)+1:03d}",
                            "name": f"WATCH_{str(r['service']).replace('/', '_')}",
                            "pattern_type": "beaconing",
                            "match_criteria": {"dst_ip": ip, "protocol": r["protocol"],
                                               "dst_port": port},
                            "severity": "MEDIUM",
                            "comment": f"service {r['service']} — cadence normale "
                                       f"{thr.get(r['service'])} s"})
    return {"chain_id": f"chain_{chain['app']}_comportement",
            "source_app_name": chain["app"],
            "global_risk_level": "MEDIUM",
            "firewall_rules": fw, "ids_signatures": ids, "ips_actions": []}


def summary(dep: dict) -> str:
    a = sum(1 for r in dep["firewall_rules"] if r["action"] == "ALLOW")
    i = sum(1 for r in dep["firewall_rules"] if r["action"] == "ALLOW_AND_INSPECT")
    return (f"chaîne « {dep['chain_id']} » : {len(dep['firewall_rules'])} règles pare-feu "
            f"({a} ALLOW, {i} ALLOW_AND_INSPECT) · {len(dep['ids_signatures'])} signatures IDS")


if __name__ == "__main__":
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from tools.behavior_traces import enrich
    from tools.behavior_chain import reference_chain
    app = sys.argv[1] if len(sys.argv) > 1 else "viber"
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else None
    dep = to_deployable(reference_chain(enrich(app)), max_ip=cap)
    out = pathlib.Path(f"/home/kali/Desktop/demo_run/chain_{app}_comportement.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(dep, indent=1, ensure_ascii=False))
    print(summary(dep))
    print("→", out)
    for r in dep["firewall_rules"][:6]:
        print(f"   {r['action']:<18} {r['dst_ip']:<16} port={r['dst_port']} {r['protocol']}")
    print("   …")
