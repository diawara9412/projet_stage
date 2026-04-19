from fastapi import APIRouter

from api.schemas import EvaluationRequest
from evaluation.evaluator import Evaluator

router = APIRouter()
evaluator = Evaluator()


@router.post("/")
def evaluate(payload: EvaluationRequest) -> dict:
    return evaluator.evaluate(payload.generated_rule, payload.context, payload.confusion)
