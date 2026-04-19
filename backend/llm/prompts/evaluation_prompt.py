def build_evaluation_prompt(generated_rule: dict, expected_behavior: str) -> str:
    return (
        "Evaluate the quality of this security rule and score relevance from 0 to 1. "
        f"Rule: {generated_rule}. Expected: {expected_behavior}"
    )
