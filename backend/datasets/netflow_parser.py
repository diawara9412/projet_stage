from pathlib import Path


class NetflowParser:
    def parse_csv(self, csv_path: str) -> list[dict]:
        path = Path(csv_path)
        if not path.exists():
            raise FileNotFoundError(csv_path)
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        if len(lines) <= 1:
            return []
        headers = [h.strip() for h in lines[0].split(",")]
        flows = []
        for line in lines[1:]:
            values = [v.strip() for v in line.split(",")]
            flows.append(dict(zip(headers, values, strict=False)))
        return flows
