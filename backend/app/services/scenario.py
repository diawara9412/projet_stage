from __future__ import annotations

from ipaddress import ip_address, ip_network


def _zone_for_ip(ip: str, zones: dict[str, list[str]]) -> str:
    target = ip_address(ip)
    for zone_name, cidrs in zones.items():
        for cidr in cidrs:
            if target in ip_network(cidr):
                return zone_name
    return "external"


def build_scenario(flows: list[dict]) -> dict:
    zones = {
        "internal": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "dmz": ["100.64.0.0/10"],
        "external": ["0.0.0.0/0"],
    }

    aggregated = []
    for flow in flows:
        src_zone = _zone_for_ip(flow["src_ip"], zones)
        dst_zone = _zone_for_ip(flow["dst_ip"], zones)
        tags = set(flow.get("tags", []))

        if src_zone == "external" and dst_zone != "external":
            tags.add("external_ingress")
        if flow.get("app_hint") in {"mysql", "postgres"}:
            tags.add("data_store")
        if flow["dst_port"] in {22, 3389, 502, 1883}:
            tags.add("sensitive")

        aggregated.append(
            {
                "src": flow["src_ip"],
                "dst": flow["dst_ip"],
                "protocol": flow["protocol"],
                "ports": {"src": flow["src_port"], "dst": flow["dst_port"]},
                "bytes": flow["bytes"],
                "packets": flow["packets"],
                "zones": {"src": src_zone, "dst": dst_zone},
                "tags": sorted(tags),
                "app_hint": flow.get("app_hint", "unknown"),
            }
        )

    security_requirements = [
        {
            "id": "ingress-web",
            "description": "External web ingress must include WAF then firewall",
            "match_tags": ["external_ingress"],
            "must_include_functions_in_order": ["waf", "firewall"],
        },
        {
            "id": "sensitive-ids",
            "description": "Sensitive flows must include IDS",
            "match_tags": ["sensitive"],
            "must_include_functions_in_order": ["ids"],
        },
    ]

    return {
        "zones": zones,
        "aggregated_flows": aggregated,
        "security_requirements": security_requirements,
        "function_catalog": [
            {
                "name": "waf",
                "image": "owasp/modsecurity-crs:nginx",
                "ports": [80, 443],
            },
            {
                "name": "firewall",
                "image": "networkstatic/iptables:latest",
                "ports": [8080],
            },
            {
                "name": "ids",
                "image": "jasonish/suricata:latest",
                "ports": [9090],
            },
        ],
        "output_constraints": {
            "output_format": "json",
            "max_chain_length": 4,
            "kubernetes_target": "kind",
            "gateway_api": True,
        },
    }
