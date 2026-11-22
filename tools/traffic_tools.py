"""
Traffic tools — Python functions called by the TrafficGenerator agent.

Provides four @tool-decorated functions to generate legitimate network
traffic on the active Mininet topology and capture it to PCAP files.

The active Mininet network is retrieved from topology_tools via
``get_active_network()``.  Deploy a topology first with
``deploy_topology_in_mininet`` before calling any function here.
"""

import json
import logging
import re
import time
from pathlib import Path

from langchain_core.tools import tool

from tools.topology_tools import get_active_network

logger = logging.getLogger(__name__)

CAPTURES_DIR = Path(__file__).parent.parent / "captures"


# ---------------------------------------------------------------------------
# Tool 1 — list_hosts_in_network
# ---------------------------------------------------------------------------

@tool
def list_hosts_in_network() -> list:
    """List all hosts in the currently deployed Mininet network.

    Retrieves host metadata (name, IP, MAC) from the globally running
    Mininet network.  Call this after deploy_topology_in_mininet to know
    which host names are valid for the other traffic and attack tools.

    Args:
        None

    Returns:
        list[dict]: One entry per host, each with keys:
            - name (str): Mininet host name, e.g. "h0"
            - ip (str): assigned IP address, e.g. "10.0.0.1"
            - mac (str): MAC address

    Examples:
        >>> list_hosts_in_network.invoke({})
        [{"name": "h0", "ip": "10.0.0.1", "mac": "b2:9c:..."},
         {"name": "h1", "ip": "10.0.0.2", "mac": "..."}, ...]
    """
    net = get_active_network()
    if net is None:
        return [{"status": "error", "message": "No active Mininet network. Call deploy_topology_in_mininet first."}]

    try:
        hosts = [
            {"name": h.name, "ip": h.IP(), "mac": h.MAC()}
            for h in net.hosts
        ]
        logger.info("Listed %d hosts in active Mininet network", len(hosts))
        return hosts

    except Exception as exc:
        logger.error("list_hosts_in_network failed: %s", exc)
        return [{"status": "error", "message": str(exc)}]


# ---------------------------------------------------------------------------
# Tool 2 — generate_http_flow
# ---------------------------------------------------------------------------

@tool
def generate_http_flow(source_host: str, destination_host: str, duration: int) -> dict:
    """Generate HTTP traffic between two Mininet hosts.

    Starts a Python HTTP server on the destination host (port 8080), then
    sends repeated curl GET requests from the source host for the requested
    duration.  Suitable for generating realistic HTTP traffic patterns in
    PCAP captures.

    Args:
        source_host (str): Name of the host that sends HTTP requests,
            e.g. "h0".
        destination_host (str): Name of the host that runs the HTTP server,
            e.g. "h1".
        duration (int): How long to generate traffic, in seconds (>= 1).

    Returns:
        dict:
            - status (str): "success" or "error"
            - message (str): summary
            - source (str): source host name
            - destination (str): destination host name
            - destination_ip (str): destination IP used
            - total_requests (int): number of completed curl requests
            - total_bytes (int): total bytes downloaded
            - actual_duration_s (float): measured wall-clock duration
            - requests_per_second (float): throughput

    Examples:
        >>> generate_http_flow.invoke({
        ...     "source_host": "h0",
        ...     "destination_host": "h1",
        ...     "duration": 10
        ... })
        {"status": "success", "total_requests": 47, "total_bytes": 23500, ...}
    """
    net = get_active_network()
    if net is None:
        return {"status": "error", "message": "No active Mininet network."}

    try:
        src = net.get(source_host)
        dst = net.get(destination_host)
    except KeyError as exc:
        return {"status": "error", "message": f"Host not found: {exc}"}

    dst_ip = dst.IP()

    try:
        # Start HTTP server on destination in background
        server_proc = dst.popen(["python3", "-m", "http.server", "8080"])
        time.sleep(0.5)  # allow server to bind

        total_requests = 0
        total_bytes = 0
        start_time = time.time()

        logger.info("Starting HTTP flow: %s → %s (%ds)", source_host, destination_host, duration)

        while time.time() - start_time < duration:
            raw = src.cmd(f"curl -sf http://{dst_ip}:8080 -o /dev/null -w '%{{size_download}}'")
            try:
                total_bytes += int(raw.strip())
                total_requests += 1
            except ValueError:
                pass  # curl failed (server not ready yet)

        actual_duration = round(time.time() - start_time, 2)

    finally:
        # Always stop the server even if an exception occurs
        try:
            server_proc.terminate()
            server_proc.wait(timeout=3)
        except Exception:
            pass
        # Kill any remaining server process inside the namespace
        dst.cmd("pkill -f 'http.server 8080' 2>/dev/null || true")

    logger.info(
        "HTTP flow done: %d requests, %d bytes in %.1fs",
        total_requests, total_bytes, actual_duration,
    )

    return {
        "status": "success",
        "message": f"Generated {total_requests} HTTP requests over {actual_duration}s",
        "source": source_host,
        "destination": destination_host,
        "destination_ip": dst_ip,
        "total_requests": total_requests,
        "total_bytes": total_bytes,
        "actual_duration_s": actual_duration,
        "requests_per_second": round(total_requests / actual_duration, 2) if actual_duration > 0 else 0,
    }


# ---------------------------------------------------------------------------
# Tool 3 — generate_iperf_flow
# ---------------------------------------------------------------------------

@tool
def generate_iperf_flow(
    source_host: str,
    destination_host: str,
    duration: int,
    bandwidth: str = "10M",
) -> dict:
    """Generate a measured bandwidth flow between two Mininet hosts using iperf3.

    Starts an iperf3 server on the destination host, then runs an iperf3
    client on the source host.  Reports throughput and packet-loss metrics
    from the iperf3 JSON output.

    Args:
        source_host (str): Host that sends traffic, e.g. "h0".
        destination_host (str): Host that receives traffic, e.g. "h1".
        duration (int): Test duration in seconds (>= 1).
        bandwidth (str): Target sending rate as iperf3 bandwidth string,
            e.g. "10M" (10 Mbit/s), "1G" (1 Gbit/s). Default "10M".

    Returns:
        dict:
            - status (str): "success" or "error"
            - message (str): summary
            - source (str): source host name
            - destination (str): destination host name
            - destination_ip (str): destination IP
            - requested_bandwidth (str): bandwidth argument passed to iperf3
            - avg_mbps (float): average throughput in Mbit/s
            - lost_percent (float): percentage of datagrams lost
            - duration_s (float): actual test duration

    Examples:
        >>> generate_iperf_flow.invoke({
        ...     "source_host": "h0",
        ...     "destination_host": "h1",
        ...     "duration": 5,
        ...     "bandwidth": "10M"
        ... })
        {"status": "success", "avg_mbps": 9.87, "lost_percent": 0.0, ...}
    """
    net = get_active_network()
    if net is None:
        return {"status": "error", "message": "No active Mininet network."}

    try:
        src = net.get(source_host)
        dst = net.get(destination_host)
    except KeyError as exc:
        return {"status": "error", "message": f"Host not found: {exc}"}

    dst_ip = dst.IP()

    try:
        # Start iperf3 server on destination
        server_proc = dst.popen(["iperf3", "-s", "--one-off"])
        time.sleep(0.3)

        logger.info(
            "Starting iperf3 flow: %s → %s (%ds @ %s)",
            source_host, destination_host, duration, bandwidth,
        )

        # Run client with JSON output for reliable parsing
        raw = src.cmd(
            f"iperf3 -c {dst_ip} -t {duration} -b {bandwidth} -J 2>&1"
        )

        # Parse iperf3 JSON result
        avg_mbps = 0.0
        lost_percent = 0.0
        actual_duration = float(duration)

        try:
            data = json.loads(raw)
            end = data.get("end", {})
            sum_sent = end.get("sum_sent", {})
            bits_per_second = sum_sent.get("bits_per_second", 0)
            avg_mbps = round(bits_per_second / 1e6, 2)
            actual_duration = round(sum_sent.get("seconds", float(duration)), 2)

            # UDP stats include lost_percent; TCP won't have this field
            sum_udp = end.get("sum", {})
            lost_percent = round(sum_udp.get("lost_percent", 0.0), 2)
        except (json.JSONDecodeError, KeyError, TypeError):
            logger.warning("Could not parse iperf3 JSON output; raw: %s", raw[:200])

    finally:
        try:
            server_proc.terminate()
            server_proc.wait(timeout=3)
        except Exception:
            pass
        dst.cmd("pkill iperf3 2>/dev/null || true")

    logger.info("iperf3 flow done: %.2f Mbit/s, %.1f%% loss", avg_mbps, lost_percent)

    return {
        "status": "success",
        "message": f"iperf3 flow: {avg_mbps} Mbit/s over {actual_duration}s",
        "source": source_host,
        "destination": destination_host,
        "destination_ip": dst_ip,
        "requested_bandwidth": bandwidth,
        "avg_mbps": avg_mbps,
        "lost_percent": lost_percent,
        "duration_s": actual_duration,
    }


# ---------------------------------------------------------------------------
# Tool 4 — start_traffic_capture
# ---------------------------------------------------------------------------

@tool
def start_traffic_capture(host_name: str, output_filename: str) -> dict:
    """Start a tcpdump packet capture on a Mininet host's network interface.

    Runs tcpdump inside the host's network namespace, writing packets to a
    .pcap file in the captures/ directory.  Returns the process PID so the
    caller can stop the capture later with ``kill <pid>``.

    Args:
        host_name (str): Name of the Mininet host to capture on, e.g. "h0".
            tcpdump will listen on its primary interface ({host_name}-eth0).
        output_filename (str): Base name for the output file (no extension),
            e.g. "abilene_run1".  Saved as captures/<output_filename>.pcap.

    Returns:
        dict:
            - status (str): "success" or "error"
            - message (str): summary
            - host (str): host name
            - interface (str): interface being captured (e.g. "h0-eth0")
            - output_file (str): absolute path to the .pcap file
            - pid (int): PID of the tcpdump process (use to stop the capture)

    Examples:
        >>> start_traffic_capture.invoke({
        ...     "host_name": "h0",
        ...     "output_filename": "abilene_run1"
        ... })
        {"status": "success", "pid": 12345, "output_file": ".../abilene_run1.pcap"}
    """
    net = get_active_network()
    if net is None:
        return {"status": "error", "message": "No active Mininet network."}

    try:
        host = net.get(host_name)
    except KeyError:
        return {"status": "error", "message": f"Host '{host_name}' not found in network."}

    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    output_path = CAPTURES_DIR / f"{output_filename}.pcap"
    interface = f"{host_name}-eth0"

    try:
        proc = host.popen([
            "tcpdump",
            "-i", interface,
            "-w", str(output_path),
            "-U",          # write each packet immediately (unbuffered)
            "--immediate-mode",
        ])

        logger.info(
            "Started tcpdump on %s (%s) → %s (PID %d)",
            host_name, interface, output_path, proc.pid,
        )

        return {
            "status": "success",
            "message": f"Capture started on {interface}",
            "host": host_name,
            "interface": interface,
            "output_file": str(output_path),
            "pid": proc.pid,
        }

    except Exception as exc:
        logger.error("start_traffic_capture failed: %s", exc)
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Quick standalone test (import checks only — no Mininet needed)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from pathlib import Path

    # Allow running as a script from the project root
    sys.path.insert(0, str(Path(__file__).parent.parent))

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    print("=== Import check ===")
    from tools.traffic_tools import (
        list_hosts_in_network,
        generate_http_flow,
        generate_iperf_flow,
        start_traffic_capture,
    )
    print("All traffic_tools functions imported OK")

    print("\n=== list_hosts_in_network (no network active) ===")
    import json
    print(json.dumps(list_hosts_in_network.invoke({}), indent=2))

    print("\nNote: functional tests require a running Mininet network.")
    print("Deploy a topology first with deploy_topology_in_mininet (sudo required).")
