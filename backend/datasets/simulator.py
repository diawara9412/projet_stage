from datetime import UTC, datetime


class TrafficSimulator:
    def generate_malicious_flow(self, attack_type: str = "port_scan") -> dict:
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "attack_type": attack_type,
            "src_ip": "192.168.56.10",
            "dst_ip": "192.168.56.1",
            "dst_port": 22,
            "protocol": "tcp",
            "payload": "simulated-malicious-traffic",
        }

    def run_mininet_stub(self, topology_name: str) -> dict:
        return {
            "topology": topology_name,
            "status": "simulated",
            "pcap_path": f"/tmp/{topology_name}.pcap",
        }
