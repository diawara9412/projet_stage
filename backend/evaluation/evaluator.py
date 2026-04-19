import time

from evaluation.llm_judge import LLMJudge
from evaluation.metrics import f1_score, precision, recall


class Evaluator:
    def __init__(self) -> None:
        self.judge = LLMJudge()

    def evaluate(self, generated_rule: dict, context: dict, confusion: dict | None = None) -> dict:
        confusion = confusion or {"tp": 1, "fp": 0, "fn": 0}
        start = time.perf_counter()
        rel = self.judge.relevance_score(generated_rule, context)
        elapsed = time.perf_counter() - start
        tp, fp, fn = confusion["tp"], confusion["fp"], confusion["fn"]
        return {
            "relevance": rel,
            "precision": precision(tp, fp),
            "recall": recall(tp, fn),
            "f1_score": f1_score(tp, fp, fn),
            "generation_time_seconds": elapsed,
        }
