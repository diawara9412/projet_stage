from pydantic import BaseModel, Field


class RuleGenerationRequest(BaseModel):
    context: dict = Field(default_factory=dict)
    provider: str = "gpt"
    output_formats: list[str] = Field(default_factory=lambda: ["snort", "iptables"])


class RuleGenerationResponse(BaseModel):
    abstract: dict
    concrete: dict
    rule: dict


class EvaluationRequest(BaseModel):
    generated_rule: dict
    context: dict = Field(default_factory=dict)
    confusion: dict = Field(default_factory=lambda: {"tp": 1, "fp": 0, "fn": 0})
