class LLMJudge:
    def relevance_score(self, generated_rule: dict, context: dict) -> float:
        target_port = context.get("dst_port")
        return 1.0 if target_port and generated_rule.get("dst_port") == target_port else 0.6
