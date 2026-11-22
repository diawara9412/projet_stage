"""
Topology tools — Python functions called by the TopologyDesigner agent.

Provides three @tool-decorated functions to discover, analyse, and deploy
network topologies from Internet Topology Zoo .graphml files into a live
Mininet simulation.

Global state
------------
``_active_network`` and ``_active_topology_name`` are module-level variables
that hold the currently running Mininet network.  Other tool modules
(traffic_tools, attack_tools) retrieve it via ``get_active_network()``.
"""

import logging
from functools import partial
from pathlib import Path
from typing import Any

import networkx as nx
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# Absolute path regardless of the working directory when the module is imported
TOPOLOGIES_DIR = Path(__file__).parent.parent / "topologies"

# ---------------------------------------------------------------------------
# Shared global state — read by traffic_tools and attack_tools
# ---------------------------------------------------------------------------
_active_network: Any = None
_active_topology_name: str | None = None


def get_active_network() -> Any:
    """Return the currently running Mininet network object, or None."""
    return _active_network


def get_active_topology_name() -> str | None:
    """Return the name of the active topology, or None."""
    return _active_topology_name


def _stop_active_network() -> None:
    """Stop and clean up the active Mininet network if one is running."""
    global _active_network, _active_topology_name
    if _active_network is not None:
        try:
            _active_network.stop()
            logger.info("Stopped Mininet network '%s'", _active_topology_name)
        except Exception as exc:
            logger.warning("Error while stopping network: %s", exc)
        _active_network = None
        _active_topology_name = None


# ---------------------------------------------------------------------------
# Tool 1 — list_available_topologies
# ---------------------------------------------------------------------------

@tool
def list_available_topologies() -> list:
    """List all .graphml topology files available for simulation.

    Scans the topologies/ directory and returns basic statistics for each
    file found.  Call this first to discover which topologies can be
    deployed before choosing one.

    Args:
        None

    Returns:
        list[dict]: One entry per .graphml file, each with keys:
            - name (str): topology name without extension (e.g. "Abilene")
            - nodes (int): number of network nodes
            - edges (int): number of links
            - filepath (str): absolute path to the .graphml file

    Examples:
        >>> list_available_topologies.invoke({})
        [{"name": "Abilene", "nodes": 11, "edges": 14, "filepath": "..."},
         {"name": "Geant2012", "nodes": 40, "edges": 61, "filepath": "..."}]
    """
    try:
        if not TOPOLOGIES_DIR.exists():
            logger.error("Topologies directory not found: %s", TOPOLOGIES_DIR)
            return [{"status": "error", "message": f"Directory not found: {TOPOLOGIES_DIR}"}]

        result = []
        for fp in sorted(TOPOLOGIES_DIR.glob("*.graphml")):
            try:
                G = nx.read_graphml(fp)
                result.append({
                    "name": fp.stem,
                    "nodes": G.number_of_nodes(),
                    "edges": G.number_of_edges(),
                    "filepath": str(fp.resolve()),
                })
            except Exception as exc:
                logger.warning("Cannot parse %s: %s", fp.name, exc)

        logger.info("Found %d topologies in %s", len(result), TOPOLOGIES_DIR)
        return result

    except Exception as exc:
        logger.error("list_available_topologies failed: %s", exc)
        return [{"status": "error", "message": str(exc)}]


# ---------------------------------------------------------------------------
# Tool 2 — inspect_topology
# ---------------------------------------------------------------------------

@tool
def inspect_topology(topology_name: str) -> dict:
    """Return detailed structural statistics for a .graphml topology file.

    Computes network metrics that help choose the right topology for a
    simulation scenario (size, connectivity, central nodes, diameter…).
    Does NOT start Mininet — safe to call any time.

    Args:
        topology_name (str): Topology name without the .graphml extension,
            e.g. "Abilene" or "Geant2012".

    Returns:
        dict:
            - status (str): "success" or "error"
            - name (str): topology name
            - nodes (int): number of nodes
            - edges (int): number of links
            - diameter (int): longest shortest-path (-1 if disconnected)
            - avg_degree (float): mean number of links per node
            - most_connected_node (str): node ID with highest degree
            - most_connected_degree (int): its degree
            - is_connected (bool): whether the graph is fully connected
            - node_list (list[str]): all node IDs

    Examples:
        >>> inspect_topology.invoke({"topology_name": "Abilene"})
        {"status": "success", "name": "Abilene", "nodes": 11, "edges": 14,
         "diameter": 5, "avg_degree": 2.55, ...}
    """
    filepath = TOPOLOGIES_DIR / f"{topology_name}.graphml"
    if not filepath.exists():
        return {"status": "error", "message": f"File not found: {filepath}"}

    try:
        G = nx.read_graphml(filepath)
        U = G.to_undirected() if G.is_directed() else G

        degrees = dict(U.degree())
        most_connected = max(degrees, key=degrees.get)
        avg_degree = sum(degrees.values()) / len(degrees) if degrees else 0.0
        is_connected = nx.is_connected(U)

        diameter = -1
        if is_connected:
            try:
                diameter = nx.diameter(U)
            except Exception:
                pass

        logger.info(
            "Inspected '%s': %d nodes, %d edges, diameter=%s",
            topology_name, G.number_of_nodes(), G.number_of_edges(), diameter,
        )

        return {
            "status": "success",
            "name": topology_name,
            "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(),
            "diameter": diameter,
            "avg_degree": round(avg_degree, 2),
            "most_connected_node": str(most_connected),
            "most_connected_degree": degrees[most_connected],
            "is_connected": is_connected,
            "node_list": [str(n) for n in G.nodes()],
        }

    except Exception as exc:
        logger.error("inspect_topology('%s') failed: %s", topology_name, exc)
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Tool 3 — deploy_topology_in_mininet
# ---------------------------------------------------------------------------

@tool
def deploy_topology_in_mininet(topology_name: str) -> dict:
    """Load a .graphml topology and start it as a live Mininet SDN network.

    Builds the Mininet topology from the graph: one OVS switch + one host
    per graph node, inter-switch links mirroring the graph edges.  Switches
    run in standalone (learning) mode — no external controller required.

    The running network is stored globally so that traffic_tools and
    attack_tools can use it immediately after.  If another topology is
    already running it is stopped cleanly first (idempotent).

    Requires root privileges (run the whole program with sudo).

    Args:
        topology_name (str): Topology name without the .graphml extension,
            e.g. "Abilene" or "Geant2012".

    Returns:
        dict:
            - status (str): "success" or "error"
            - message (str): human-readable summary
            - topology_name (str): name of the deployed topology
            - nb_hosts (int): number of hosts created
            - nb_switches (int): number of switches created
            - nb_links (int): number of inter-switch links
            - hosts (list[str]): host names ["h0", "h1", …]
            - host_ips (dict): {host_name: ip_address}

    Examples:
        >>> deploy_topology_in_mininet.invoke({"topology_name": "Abilene"})
        {"status": "success", "nb_hosts": 11, "nb_switches": 11,
         "nb_links": 14, "hosts": ["h0", ..., "h10"], ...}
    """
    global _active_network, _active_topology_name

    try:
        from mininet.net import Mininet
        from mininet.topo import Topo
        from mininet.log import setLogLevel
        from mininet.link import TCLink
        from mininet.node import OVSSwitch
    except ImportError as exc:
        return {"status": "error", "message": f"Mininet not available: {exc}"}

    filepath = TOPOLOGIES_DIR / f"{topology_name}.graphml"
    if not filepath.exists():
        return {"status": "error", "message": f"Topology file not found: {filepath}"}

    # Stop the previous network first (idempotent behaviour)
    if _active_network is not None:
        logger.info(
            "Stopping previous network '%s' before deploying '%s'",
            _active_topology_name, topology_name,
        )
        _stop_active_network()

    try:
        G = nx.read_graphml(filepath)
        nodes = list(G.nodes())
        edges = list(G.edges())

        setLogLevel("warning")

        # Standalone OVS switches act as learning bridges — no controller needed
        StandaloneSwitch = partial(OVSSwitch, failMode="standalone")

        class GraphMLTopo(Topo):
            """Dynamic Mininet topology built from a networkx graph."""

            def build(self):
                # Map each graph node ID → Mininet switch name (s0, s1, …)
                node_to_switch: dict[str, str] = {}
                for i, node_id in enumerate(nodes):
                    sw_name = f"s{i}"
                    self.addSwitch(sw_name)
                    node_to_switch[node_id] = sw_name
                    # One host per switch, IP in 10.0.0.x/8 (Mininet default range)
                    h_name = f"h{i}"
                    self.addHost(h_name)
                    self.addLink(h_name, sw_name)

                # Inter-switch links mirror the graph edges
                for src_id, dst_id in edges:
                    self.addLink(
                        node_to_switch[src_id],
                        node_to_switch[dst_id],
                    )

        topo = GraphMLTopo()
        net = Mininet(
            topo=topo,
            switch=StandaloneSwitch,
            link=TCLink,
            controller=None,   # standalone mode — aucun contrôleur OpenFlow externe
            waitConnected=False,
        )
        net.start()

        hosts = net.hosts
        host_ips = {h.name: h.IP() for h in hosts}

        _active_network = net
        _active_topology_name = topology_name

        logger.info(
            "Deployed '%s': %d switches, %d hosts, %d inter-switch links",
            topology_name, len(nodes), len(hosts), len(edges),
        )

        return {
            "status": "success",
            "message": f"Topology '{topology_name}' deployed ({len(nodes)} nodes)",
            "topology_name": topology_name,
            "nb_hosts": len(hosts),
            "nb_switches": len(nodes),
            "nb_links": len(edges),
            "hosts": [h.name for h in hosts],
            "host_ips": host_ips,
        }

    except Exception as exc:
        logger.error("deploy_topology_in_mininet('%s') failed: %s", topology_name, exc)
        _stop_active_network()
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Quick standalone test (no Mininet required for the first two functions)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    print("=== list_available_topologies ===")
    print(json.dumps(list_available_topologies.invoke({}), indent=2))

    print("\n=== inspect_topology: Abilene ===")
    print(json.dumps(inspect_topology.invoke({"topology_name": "Abilene"}), indent=2))

    print("\n=== inspect_topology: Geant2012 ===")
    print(json.dumps(inspect_topology.invoke({"topology_name": "Geant2012"}), indent=2))

    if "--deploy" in sys.argv:
        print("\n=== deploy_topology_in_mininet: Abilene (needs sudo) ===")
        print(json.dumps(
            deploy_topology_in_mininet.invoke({"topology_name": "Abilene"}),
            indent=2,
        ))
