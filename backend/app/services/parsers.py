from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, IPv6, TCP, UDP, rdpcap  # type: ignore

NETFLOW_REQUIRED_FIELDS = {
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packets",
    "bytes",
    "start_ts",
    "end_ts",
}


def _port_hint(port: int) -> str:
    table = {
        80: "http",
        443: "https",
        53: "dns",
        22: "ssh",
        3306: "mysql",
        5432: "postgres",
        1883: "mqtt",
        502: "modbus",
    }
    return table.get(port, "unknown")


def parse_pcap(path: Path) -> list[dict]:
    packets = rdpcap(str(path))
    flows: dict[tuple, dict] = defaultdict(dict)

    for packet in packets:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            continue

        src_ip = getattr(ip_layer, "src", None)
        dst_ip = getattr(ip_layer, "dst", None)
        if not src_ip or not dst_ip:
            continue

        protocol = "other"
        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):
            protocol = "tcp"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            protocol = "udp"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        ts = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat()
        size = int(len(packet))

        if not flows[key]:
            flows[key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packets": 0,
                "bytes": 0,
                "start_ts": ts,
                "end_ts": ts,
                "tags": [],
                "app_hint": _port_hint(dst_port),
            }

        flow = flows[key]
        flow["packets"] += 1
        flow["bytes"] += size
        flow["end_ts"] = ts

    return list(flows.values())


def _validate_flow_row(row: dict) -> None:
    missing = [field for field in NETFLOW_REQUIRED_FIELDS if field not in row]
    if missing:
        raise ValueError(f"Missing netflow fields: {', '.join(sorted(missing))}")


def parse_netflow_json(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("NetFlow JSON must be a list of flow objects")

    normalized = []
    for row in payload:
        if not isinstance(row, dict):
            raise ValueError("Each NetFlow JSON item must be an object")
        _validate_flow_row(row)
        normalized.append(
            {
                **row,
                "src_port": int(row["src_port"]),
                "dst_port": int(row["dst_port"]),
                "packets": int(row["packets"]),
                "bytes": int(row["bytes"]),
                "tags": row.get("tags", []),
                "app_hint": row.get("app_hint") or _port_hint(int(row["dst_port"])),
            }
        )
    return normalized


def parse_netflow_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    normalized = []
    for row in rows:
        _validate_flow_row(row)
        normalized.append(
            {
                **row,
                "src_port": int(row["src_port"]),
                "dst_port": int(row["dst_port"]),
                "packets": int(row["packets"]),
                "bytes": int(row["bytes"]),
                "tags": row.get("tags", "").split("|") if row.get("tags") else [],
                "app_hint": row.get("app_hint") or _port_hint(int(row["dst_port"])),
            }
        )
    return normalized


def parse_upload(path: Path, file_type: str) -> list[dict]:
    if file_type == "pcap":
        return parse_pcap(path)
    if file_type == "netflow_json":
        return parse_netflow_json(path)
    if file_type == "netflow_csv":
        return parse_netflow_csv(path)
    raise ValueError(f"Unsupported file type: {file_type}")
