from __future__ import annotations

import csv
import json
from pathlib import Path

from jsonschema import ValidationError, validate

PLAN_SCHEMA = {
    "type": "object",
    "required": ["chains"],
    "properties": {
        "chains": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["name", "selectors", "functions"],
                "properties": {
                    "name": {"type": "string"},
                    "selectors": {"type": "object"},
                    "functions": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string"},
                    },
                },
            },
        }
    },
}

FORBIDDEN = {"drop_all", "allow_all"}


def schema_validity(plan: dict) -> tuple[bool, str]:
    try:
        validate(instance=plan, schema=PLAN_SCHEMA)
        return True, "ok"
    except ValidationError as exc:
        return False, str(exc)


def policy_compliance(plan: dict, scenario: dict) -> tuple[float, list[str]]:
    requirements = scenario.get("security_requirements", [])
    chains = plan.get("chains", [])
    if not requirements:
        return 1.0, []

    total = 0
    passed = 0
    failures: list[str] = []

    for req in requirements:
        required = req.get("must_include_functions_in_order", [])
        for chain in chains:
            total += 1
            fn = chain.get("functions", [])
            idx = 0
            for item in fn:
                if idx < len(required) and item == required[idx]:
                    idx += 1
            if idx == len(required):
                passed += 1
            else:
                failures.append(f"{req.get('id', 'requirement')} failed for {chain.get('name')}")

    return (passed / total) if total else 0.0, failures


def chain_coherence(plan: dict) -> tuple[bool, list[str]]:
    issues: list[str] = []
    for chain in plan.get("chains", []):
        functions = chain.get("functions", [])
        if any(item in FORBIDDEN for item in functions):
            issues.append(f"forbidden function in {chain.get('name')}")
        if "waf" in functions and "firewall" in functions:
            if functions.index("waf") > functions.index("firewall"):
                issues.append(f"waf should appear before firewall in {chain.get('name')}")
    return (len(issues) == 0), issues


def save_metrics(metrics: list[dict], json_path: Path, csv_path: Path) -> None:
    json_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    fieldnames = [
        "provider",
        "latency_ms",
        "schema_valid",
        "policy_score",
        "coherent",
        "issues",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in metrics:
            writer.writerow(
                {
                    "provider": item["provider"],
                    "latency_ms": round(item["latency_ms"], 2),
                    "schema_valid": item["schema_valid"],
                    "policy_score": item["policy_score"],
                    "coherent": item["coherent"],
                    "issues": "|".join(item["issues"]),
                }
            )
