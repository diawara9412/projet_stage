class SnortFormatter:
    def format(self, rule: dict) -> str:
        action = rule.get("action", "alert")
        proto = rule.get("protocol", "tcp")
        src = rule.get("src_ip", "any")
        dst = rule.get("dst_ip", "any")
        msg = rule.get("message", "Auto-generated rule")
        sid = rule.get("sid", 1000001)
        return f"{action} {proto} {src} any -> {dst} any (msg:\"{msg}\"; sid:{sid};)"
