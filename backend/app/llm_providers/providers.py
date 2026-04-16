from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ProviderResult:
    provider: str
    available: bool
    latency_ms: float
    plan: dict
    raw: str


def build_default_plan(scenario: dict) -> dict:
    chains = []
    for flow in scenario.get("aggregated_flows", []):
        tags = flow.get("tags", [])
        functions: list[str] = []
        if "external_ingress" in tags:
            functions.extend(["waf", "firewall"])
        elif "data_store" in tags:
            functions.extend(["firewall", "ids"])
        elif "sensitive" in tags:
            functions.extend(["firewall", "ids"])
        else:
            functions.append("firewall")
        if "ids" not in functions:
            functions.append("ids")

        chains.append(
            {
                "name": f"chain-{flow['app_hint']}-{flow['ports']['dst']}",
                "selectors": {
                    "tags": tags,
                    "dst_port": flow["ports"]["dst"],
                    "protocol": flow["protocol"],
                },
                "functions": functions,
            }
        )
    if not chains:
        chains.append(
            {
                "name": "chain-default",
                "selectors": {"tags": ["default"]},
                "functions": ["firewall", "ids"],
            }
        )
    return {"chains": chains}


class BaseProvider:
    name = "base"

    def available(self) -> bool:
        raise NotImplementedError

    async def generate(self, scenario: dict) -> ProviderResult:
        raise NotImplementedError


class OllamaProvider(BaseProvider):
    name = "llama_ollama"

    def available(self) -> bool:
        return bool(settings.ollama_base_url)

    async def generate(self, scenario: dict) -> ProviderResult:
        started = time.perf_counter()
        default = build_default_plan(scenario)
        if not self.available():
            return ProviderResult(self.name, False, 0, default, "")

        prompt = (
            "Return strict JSON with key chains[{name,selectors{tags,dst_port,protocol},functions}] "
            "for this scenario: "
            + json.dumps(scenario)
        )
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.post(
                    f"{settings.ollama_base_url}/api/generate",
                    json={
                        "model": settings.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                    },
                )
                response.raise_for_status()
                raw = response.json().get("response", "")
                plan = json.loads(raw)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.warning("Ollama generation failed, falling back to default plan: %s", exc)
            raw = "fallback-default-plan"
            plan = default

        return ProviderResult(self.name, True, (time.perf_counter() - started) * 1000, plan, raw)


class OptionalAPIProvider(BaseProvider):
    def __init__(self, name: str, api_key: str | None):
        self.name = name
        self.api_key = api_key

    def available(self) -> bool:
        return bool(self.api_key)

    async def generate(self, scenario: dict) -> ProviderResult:
        started = time.perf_counter()
        plan = build_default_plan(scenario)
        # Offline-safe deterministic variation for comparison.
        if self.name == "mistral" and plan["chains"]:
            plan["chains"][0]["functions"] = ["firewall", "ids"]
        if self.name == "openai_gpt4_1" and plan["chains"]:
            plan["chains"][0]["functions"] = ["waf", "firewall", "ids"]
        if self.name == "anthropic_claude" and plan["chains"]:
            plan["chains"][0]["functions"] = ["firewall", "waf", "ids"]

        return ProviderResult(
            provider=self.name,
            available=self.available(),
            latency_ms=(time.perf_counter() - started) * 1000,
            plan=plan,
            raw="simulated-plan",
        )


def get_provider_registry() -> dict[str, BaseProvider]:
    return {
        "llama_ollama": OllamaProvider(),
        "mistral": OptionalAPIProvider("mistral", settings.mistral_api_key),
        "openai_gpt4_1": OptionalAPIProvider("openai_gpt4_1", settings.openai_api_key),
        "anthropic_claude": OptionalAPIProvider("anthropic_claude", settings.anthropic_api_key),
    }
