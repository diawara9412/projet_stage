import json

from llm.llm_factory import LLMFactory
from llm.prompts.security_prompt import build_security_prompt
from rules_generation.abstract_formatter import AbstractFormatter
from rules_generation.concrete_formatters.dlp_formatter import DLPFormatter
from rules_generation.concrete_formatters.iptables_formatter import IptablesFormatter
from rules_generation.concrete_formatters.openflow_formatter import OpenFlowFormatter
from rules_generation.concrete_formatters.snort_formatter import SnortFormatter
from rules_generation.validator import RuleValidator


class RuleGenerator:
    def __init__(self) -> None:
        self.validator = RuleValidator()
        self.formatters = {
            "openflow": OpenFlowFormatter(),
            "snort": SnortFormatter(),
            "iptables": IptablesFormatter(),
            "dlp": DLPFormatter(),
        }

    def generate(self, context: dict, provider: str, output_formats: list[str]) -> dict:
        prompt = build_security_prompt(context)
        llm = LLMFactory.create(provider)
        raw = llm.generate(prompt)
        parsed = self._safe_parse(raw)
        rule = parsed.get("rules", [{}])[0] | context.get("seed_rule", {})

        is_valid, reason = self.validator.validate(rule)
        if not is_valid:
            raise ValueError(reason)

        abstract = {
            "json": AbstractFormatter.to_json({"rules": [rule]}),
            "yaml": AbstractFormatter.to_yaml({"rules": [rule]}),
        }
        concrete = {
            fmt: self.formatters[fmt].format(rule)
            for fmt in output_formats
            if fmt in self.formatters
        }
        return {"abstract": abstract, "concrete": concrete, "rule": rule}

    @staticmethod
    def _safe_parse(raw: str) -> dict:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"rules": [{"action": "alert", "protocol": "tcp", "message": raw}]}
