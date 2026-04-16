from __future__ import annotations

import asyncio
import json
import logging
import zipfile
from pathlib import Path

import yaml

from app.core.config import settings
from app.core.db import update_run
from app.llm_providers.providers import ProviderResult, get_provider_registry
from app.services.evaluators import chain_coherence, policy_compliance, save_metrics, schema_validity
from app.services.renderer import ManifestRenderer

logger = logging.getLogger(__name__)


async def execute_run(run_id: str, run_dir: Path, scenario: dict, selected_models: list[str], repeats: int = 1) -> dict:
    registry = get_provider_registry()
    renderer = ManifestRenderer(Path(__file__).resolve().parents[1] / "templates")

    providers = [registry[name] for name in selected_models if name in registry]
    results: list[dict] = []

    for provider in providers:
        sample_results: list[ProviderResult] = []
        for _ in range(max(1, repeats)):
            sample_results.append(await provider.generate(scenario))

        latest = sample_results[-1]
        plan = latest.plan
        valid, schema_issue = schema_validity(plan)
        policy_score, policy_issues = policy_compliance(plan, scenario)
        coherent, coherence_issues = chain_coherence(plan)
        issues = [x for x in [schema_issue] if x != "ok"] + policy_issues + coherence_issues

        provider_dir = run_dir / provider.name
        provider_dir.mkdir(parents=True, exist_ok=True)
        plan_path = provider_dir / "plan.json"
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        renderer.render(scenario, plan, provider_dir)

        results.append(
            {
                "provider": provider.name,
                "available": latest.available,
                "latency_ms": latest.latency_ms,
                "schema_valid": valid,
                "policy_score": round(policy_score, 4),
                "coherent": coherent,
                "issues": issues,
                "plan_path": str(plan_path),
            }
        )

    metrics_json = run_dir / "metrics.json"
    metrics_csv = run_dir / "metrics.csv"
    save_metrics(results, metrics_json, metrics_csv)

    scenario_path = run_dir / "scenario.yaml"
    scenario_path.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")

    export_path = run_dir / "export.zip"
    with zipfile.ZipFile(export_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(scenario_path, "scenario.yaml")
        archive.write(metrics_json, "metrics.json")
        archive.write(metrics_csv, "metrics.csv")
        for provider in providers:
            provider_dir = run_dir / provider.name
            for file in provider_dir.iterdir():
                archive.write(file, f"{provider.name}/{file.name}")

    payload = {
        "run_id": run_id,
        "status": "completed",
        "results": results,
        "metrics_json": str(metrics_json),
        "metrics_csv": str(metrics_csv),
        "export": str(export_path),
    }

    update_run(
        run_id,
        status="completed",
        result_artifact=json.dumps(payload),
        metrics_json=str(metrics_json),
        metrics_csv=str(metrics_csv),
    )
    return payload


async def execute_and_store(run_id: str, run_dir: Path, scenario: dict, selected_models: list[str], repeats: int) -> None:
    try:
        await execute_run(run_id, run_dir, scenario, selected_models, repeats)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Run execution failed for run_id=%s", run_id)
        update_run(run_id, status="failed", result_artifact=json.dumps({"error": str(exc)}))
