"""
Attack tools — Python functions called by the AttackSimulator agent.

Provides three @tool-decorated functions to inject adversarial traffic into
the active Mininet topology: SYN flood, port scan, and impact measurement.

The active Mininet network is retrieved from topology_tools via
``get_active_network()``.  Deploy a topology first with
``deploy_topology_in_mininet`` before calling any function here.
"""

import logging
import re
import time

from langchain_core.tools import tool

from tools.topology_tools import get_active_network

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_ping_stats(ping_output: str) -> dict:
    """Extract packet-loss % and avg RTT ms from ping command output."""
    loss = 100.0
    avg_rtt = -1.0

    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", ping_output)
    if loss_match:
        loss = float(loss_match.group(1))

    rtt_match = re.search(r"rtt .* = [\d.]+/([\d.]+)/", ping_output)
    if rtt_match:
        avg_rtt = float(rtt_match.group(1))

    return {"loss_percent": loss, "avg_rtt_ms": avg_rtt}


# ---------------------------------------------------------------------------
# Tool 1 — launch_syn_flood
# ---------------------------------------------------------------------------

@tool
def launch_syn_flood(
    attacker_host: str,
    victim_host: str,
    duration: int,
    packets_per_second: int = 10000,
) -> dict:
    """Launch a TCP SYN flood attack from one Mininet host to another.

    Runs hping3 in SYN flood mode from the attacker host targeting port 80
    of the victim host for the specified duration.  Uses the Linux ``timeout``
    command to enforce the time limit.  Suitable for generating DDoS-style
    attack traffic visible in PCAP captures.

    Args:
        attacker_host (str): Mininet host that sends the flood, e.g. "h0".
        victim_host (str): Mininet host that receives the flood, e.g. "h1".
        duration (int): Attack duration in seconds (>= 1).
        packets_per_second (int): Approximate packet rate.  Values above
            ~50 000 use --flood mode (max rate); lower values use
            --faster or an inter-packet interval. Default 10 000.

    Returns:
        dict:
            - status (str): "success" or "error"
            - message (str): summary
            - attacker (str): attacker host name
            - victim (str): victim host name
            - attacker_ip (str): attacker IP
            - victim_ip (str): victim IP
            - duration_s (int): requested duration
            - packets_sent (int): number of SYN packets sent (parsed from
              hping3 statistics, -1 if parsing failed)
            - mode (str): "flood" or "rate-limited"

    Examples:
        >>> launch_syn_flood.invoke({
        ...     "attacker_host": "h0",
        ...     "victim_host": "h1",
        ...     "duration": 5
        ... })
        {"status": "success", "packets_sent": 48231, "mode": "flood", ...}
    """
    net = get_active_network()
    if net is None:
        return {"status": "error", "message": "No active Mininet network."}

    try:
        attacker = net.get(attacker_host)
        victim = net.get(victim_host)
    except KeyError as exc:
        return {"status": "error", "message": f"Host not found: {exc}"}

    attacker_ip = attacker.IP()
    victim_ip = victim.IP()

    # Choose hping3 rate mode
    if packets_per_second >= 50_000:
        rate_flag = "--flood"
        mode = "flood"
    else:
        # --interval u<microseconds> controls the rate
        interval_us = max(1, 1_000_000 // packets_per_second)
        rate_flag = f"--interval u{interval_us}"
        mode = "rate-limited"

    cmd = (
        f"timeout {duration} "
        f"hping3 -S {rate_flag} -p 80 --rand-source {victim_ip} 2>&1 || true"
    )

    logger.info(
        "Launching SYN flood: %s → %s (%ds, %s)",
        attacker_host, victim_host, duration, mode,
    )

    try:
        output = attacker.cmd(cmd)
    except Exception as exc:
        return {"status": "error", "message": f"hping3 execution failed: {exc}"}

    # Parse packet count from hping3 statistics line
    # Example: "48231 packets transmitted, 0 packets received, 100% packet loss"
    packets_sent = -1
    match = re.search(r"(\d+)\s+packets transmitted", output)
    if match:
        packets_sent = int(match.group(1))

    logger.info(
        "SYN flood done: %d packets sent in %ds", packets_sent, duration
    )

    return {
        "status": "success",
        "message": f"SYN flood completed: {packets_sent} packets in {duration}s",
        "attacker": attacker_host,
        "victim": victim_host,
        "attacker_ip": attacker_ip,
        "victim_ip": victim_ip,
        "duration_s": duration,
        "packets_sent": packets_sent,
        "mode": mode,
    }


# ---------------------------------------------------------------------------
# Tool 2 — launch_port_scan
# ---------------------------------------------------------------------------

@tool
def launch_port_scan(attacker_host: str, target_subnet: str) -> dict:
    """Run an nmap SYN port scan from a Mininet host against a target subnet.

    Executes ``nmap -sS`` (TCP SYN / half-open scan) from inside the
    attacker host's network namespace.  This generates typical reconnaissance
    traffic visible in PCAP captures and IDS datasets.

    Note: nmap -sS requires root privileges; Mininet hosts run as root by
    default, so this works without extra configuration.

    Args:
        attacker_host (str): Mininet host that performs the scan, e.g. "h0".
        target_subnet (str): CIDR range or single IP to scan,
            e.g. "10.0.0.0/24" or "10.0.0.1".

    Returns:
        dict:
            - status (str): "success" or "error"
            - message (str): summary
            - attacker (str): attacker host name
            - target_subnet (str): scanned range
            - hosts_scanned (int): number of hosts found up
            - open_ports (list[dict]): each entry has "host", "port", "service"
            - duration_s (float): wall-clock scan time
            - raw_summary (str): last few lines of nmap output

    Examples:
        >>> launch_port_scan.invoke({
        ...     "attacker_host": "h0",
        ...     "target_subnet": "10.0.0.0/24"
        ... })
        {"status": "success", "hosts_scanned": 10, "open_ports": [...], ...}
    """
    net = get_active_network()
    if net is None:
        return {"status": "error", "message": "No active Mininet network."}

    try:
        attacker = net.get(attacker_host)
    except KeyError:
        return {"status": "error", "message": f"Host '{attacker_host}' not found."}

    logger.info("Launching port scan: %s → %s", attacker_host, target_subnet)
    start_time = time.time()

    try:
        # -sS: SYN scan  -T4: aggressive timing  --open: only show open ports
        output = attacker.cmd(
            f"nmap -sS -T4 --open {target_subnet} 2>&1"
        )
    except Exception as exc:
        return {"status": "error", "message": f"nmap execution failed: {exc}"}

    duration_s = round(time.time() - start_time, 2)

    # Parse open ports
    # nmap output lines look like:  "80/tcp   open  http"
    open_ports = []
    current_host = None
    hosts_up = 0

    for line in output.splitlines():
        # Detect host header: "Nmap scan report for 10.0.0.1"
        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            current_host = host_match.group(1).strip()
            hosts_up += 1
            continue

        # Detect open port lines: "80/tcp   open  http"
        port_match = re.match(r"(\d+)/(\w+)\s+open\s+(\S*)", line)
        if port_match and current_host:
            open_ports.append({
                "host": current_host,
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "service": port_match.group(3) or "unknown",
            })

    # Last 5 lines as summary
    raw_summary = "\n".join(output.strip().splitlines()[-5:])

    logger.info(
        "Port scan done: %d hosts up, %d open ports in %.1fs",
        hosts_up, len(open_ports), duration_s,
    )

    return {
        "status": "success",
        "message": f"Scan found {hosts_up} hosts up, {len(open_ports)} open ports",
        "attacker": attacker_host,
        "target_subnet": target_subnet,
        "hosts_scanned": hosts_up,
        "open_ports": open_ports,
        "duration_s": duration_s,
        "raw_summary": raw_summary,
    }


# ---------------------------------------------------------------------------
# Tool 3 — measure_attack_impact
# ---------------------------------------------------------------------------

@tool
def measure_attack_impact(victim_host: str, baseline_duration: int = 5) -> dict:
    """Measure network latency impact on a victim host using ICMP pings.

    Selects another host as an observer and sends ICMP pings to the victim
    both before and after a potential attack to quantify degradation.
    Call this before launching an attack to record the baseline, then call
    again during or after to compare.

    Args:
        victim_host (str): Mininet host to measure, e.g. "h1".
        baseline_duration (int): How many seconds to ping for.  Sends
            10 pings/second (``-i 0.1``), so ``baseline_duration * 10``
            total packets. Default 5 s → 50 pings.

    Returns:
        dict:
            - status (str): "success" or "error"
            - message (str): summary
            - victim (str): victim host name
            - victim_ip (str): victim IP
            - observer (str): host used to send pings
            - packets_sent (int): total ICMP packets transmitted
            - loss_percent (float): packet loss percentage (0 = no drop)
            - avg_rtt_ms (float): average round-trip time in ms (-1 if all lost)
            - assessment (str): "normal", "degraded", or "unreachable"

    Examples:
        >>> measure_attack_impact.invoke({"victim_host": "h1"})
        {"status": "success", "loss_percent": 0.0, "avg_rtt_ms": 0.3,
         "assessment": "normal", ...}
    """
    net = get_active_network()
    if net is None:
        return {"status": "error", "message": "No active Mininet network."}

    try:
        victim = net.get(victim_host)
    except KeyError:
        return {"status": "error", "message": f"Host '{victim_host}' not found."}

    victim_ip = victim.IP()

    # Pick the first host that is NOT the victim as the observer
    observer = None
    for h in net.hosts:
        if h.name != victim_host:
            observer = h
            break

    if observer is None:
        return {"status": "error", "message": "Need at least 2 hosts to measure impact."}

    packet_count = baseline_duration * 10  # 10 pings/s

    logger.info(
        "Measuring latency: %s → %s (%d pings)",
        observer.name, victim_host, packet_count,
    )

    try:
        output = observer.cmd(
            f"ping -c {packet_count} -i 0.1 {victim_ip} 2>&1"
        )
    except Exception as exc:
        return {"status": "error", "message": f"ping failed: {exc}"}

    stats = _parse_ping_stats(output)
    loss = stats["loss_percent"]
    avg_rtt = stats["avg_rtt_ms"]

    # Simple qualitative assessment
    if loss >= 90:
        assessment = "unreachable"
    elif loss > 10 or (avg_rtt > 0 and avg_rtt > 100):
        assessment = "degraded"
    else:
        assessment = "normal"

    logger.info(
        "Impact measurement: %.1f%% loss, %.2f ms RTT → %s",
        loss, avg_rtt, assessment,
    )

    return {
        "status": "success",
        "message": f"Latency measurement: {assessment} ({loss}% loss, {avg_rtt} ms avg RTT)",
        "victim": victim_host,
        "victim_ip": victim_ip,
        "observer": observer.name,
        "packets_sent": packet_count,
        "loss_percent": loss,
        "avg_rtt_ms": avg_rtt,
        "assessment": assessment,
    }


# ---------------------------------------------------------------------------
# Quick standalone test (import check only — no Mininet needed)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    print("=== Import check ===")
    from tools.attack_tools import launch_syn_flood, launch_port_scan, measure_attack_impact
    print("All attack_tools functions imported OK")

    print("\n=== launch_syn_flood (no network active) ===")
    result = launch_syn_flood.invoke({
        "attacker_host": "h0",
        "victim_host": "h1",
        "duration": 3,
    })
    print(json.dumps(result, indent=2))

    print("\nNote: functional tests require a running Mininet network (sudo required).")
