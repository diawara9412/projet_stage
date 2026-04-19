class OpenFlowFormatter:
    def format(self, rule: dict) -> str:
        action = rule.get("action", "drop")
        proto = rule.get("protocol", "tcp")
        dst_port = rule.get("dst_port", "any")
        return f"table=0,priority=100,{proto},tp_dst={dst_port},actions={action.upper()}"
