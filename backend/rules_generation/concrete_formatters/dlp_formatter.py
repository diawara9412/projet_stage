class DLPFormatter:
    def format(self, rule: dict) -> str:
        pattern = rule.get("payload_pattern", "sensitive")
        action = rule.get("action", "alert")
        return f"DLP_POLICY if content matches /{pattern}/ then {action.upper()}"
