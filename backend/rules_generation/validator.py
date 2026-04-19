from config.security_rules_config import RULE_TEMPLATE


class RuleValidator:
    def validate(self, rule: dict) -> tuple[bool, str]:
        required = {"action", "protocol"}
        missing = [key for key in required if key not in rule]
        if missing:
            return False, f"Missing keys: {', '.join(missing)}"
        merged = RULE_TEMPLATE | rule
        if merged["action"] not in {"alert", "drop", "allow"}:
            return False, "Invalid action"
        return True, "ok"
