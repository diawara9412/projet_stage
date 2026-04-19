class IptablesFormatter:
    def format(self, rule: dict) -> str:
        chain = "INPUT"
        action = "DROP" if rule.get("action") == "drop" else "ACCEPT"
        proto = rule.get("protocol", "tcp")
        dst_port = rule.get("dst_port")
        port_flag = f" --dport {dst_port}" if dst_port else ""
        return f"iptables -A {chain} -p {proto}{port_flag} -j {action}"
