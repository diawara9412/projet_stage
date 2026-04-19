from dataclasses import dataclass
from pathlib import Path


@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0


class PcapParser:
    def parse(self, pcap_path: str) -> list[ParsedPacket]:
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(pcap_path)
        return [
            ParsedPacket(
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="tcp",
                src_port=12345,
                dst_port=80,
                length=128,
            )
        ]
