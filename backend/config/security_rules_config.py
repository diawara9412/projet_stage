RULE_TEMPLATE = {
    "rule_id": "",
    "action": "alert",
    "src_ip": "any",
    "dst_ip": "any",
    "src_port": "any",
    "dst_port": "any",
    "protocol": "tcp",
    "payload_pattern": "",
    "severity": "medium",
}

SUPPORTED_CONCRETE_FORMATS = ["openflow", "snort", "iptables", "dlp"]
