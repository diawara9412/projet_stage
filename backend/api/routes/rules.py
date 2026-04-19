from fastapi import APIRouter, HTTPException

from api.schemas import RuleGenerationRequest, RuleGenerationResponse
from rules_generation.rule_generator import RuleGenerator

router = APIRouter()
generator = RuleGenerator()


@router.post("/generate", response_model=RuleGenerationResponse)
def generate_rules(request: RuleGenerationRequest):
    try:
        return generator.generate(request.context, request.provider, request.output_formats)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
