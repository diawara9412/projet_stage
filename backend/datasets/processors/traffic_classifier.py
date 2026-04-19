class TrafficClassifier:
    SUSPICIOUS_PORTS = {22, 23, 3389, 445}

    def classify(self, flow: dict) -> str:
        port = int(flow.get("dst_port", 0) or 0)
        payload = str(flow.get("payload", "")).lower()
        if port in self.SUSPICIOUS_PORTS or "exploit" in payload or "malicious" in payload:
            return "suspect"
        return "legitimate"
