from fastapi import APIRouter

from datasets.simulator import TrafficSimulator

router = APIRouter()
simulator = TrafficSimulator()


@router.post("/traffic")
def simulate_traffic(attack_type: str = "port_scan") -> dict:
    return simulator.generate_malicious_flow(attack_type)
