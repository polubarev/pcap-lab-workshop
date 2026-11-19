"""Turn decoded packets into the summary, statistics and network graph the UI shows."""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

import networkx as nx

from pcap_reader import Packet
from services import service_name

TIMELINE_BUCKETS = 60

# Local-network ranges. ipaddress' is_private is not used because it also counts
# documentation and benchmarking ranges (e.g. 203.0.113.0/24) as private.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
)]


def is_internal(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in INTERNAL_NETWORKS)


def summarize(packets: list[Packet]) -> dict:
    """Totals, protocol breakdown, top talkers, top ports and a traffic timeline."""
    if not packets:
        return {"packets": 0, "bytes": 0, "hosts": 0, "duration": 0, "start": None, "end": None,
                "protocols": {}, "top_talkers": [], "top_ports": [], "timeline": []}

    start = min(p.timestamp for p in packets)
    end = max(p.timestamp for p in packets)
    protocols = Counter(p.protocol for p in packets)
    hosts = host_table(packets)

    talkers = sorted(hosts.values(), key=lambda h: h["bytes_sent"] + h["bytes_received"], reverse=True)

    return {
        "packets": len(packets),
        "bytes": sum(p.wire_length for p in packets),
        "hosts": len(hosts),
        "duration": round(end - start, 3),
        "start": start,
        "end": end,
        "protocols": dict(protocols.most_common()),
        "top_talkers": talkers[:10],
        "top_ports": top_ports(packets)[:10],
        "timeline": timeline(packets, start, end),
    }


def host_table(packets: list[Packet]) -> dict[str, dict]:
    """Per-IP counters: what each host sent and received, and who it talked to."""
    hosts: dict[str, dict] = {}
    peers: dict[str, set] = defaultdict(set)

    def entry(ip: str) -> dict:
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "internal": is_internal(ip), "packets_sent": 0, "packets_received": 0,
                         "bytes_sent": 0, "bytes_received": 0, "protocols": set(),
                         "first_seen": None, "last_seen": None}
        return hosts[ip]

    for p in packets:
        if not p.src_ip or not p.dst_ip:
            continue
        s, d = entry(p.src_ip), entry(p.dst_ip)
        s["packets_sent"] += 1
        s["bytes_sent"] += p.wire_length
        d["packets_received"] += 1
        d["bytes_received"] += p.wire_length
        for h in (s, d):
            h["protocols"].add(p.protocol)
            h["first_seen"] = p.timestamp if h["first_seen"] is None else min(h["first_seen"], p.timestamp)
            h["last_seen"] = p.timestamp if h["last_seen"] is None else max(h["last_seen"], p.timestamp)
        peers[p.src_ip].add(p.dst_ip)
        peers[p.dst_ip].add(p.src_ip)

    for ip, h in hosts.items():
        h["protocols"] = sorted(h["protocols"])
        h["peers"] = len(peers[ip])
    return hosts


def top_ports(packets: list[Packet]) -> list[dict]:
    """Most used server ports. The well-known side of a conversation counts as the server."""
    counts: Counter = Counter()
    for p in packets:
        if p.protocol not in ("TCP", "UDP") or p.dst_port is None:
            continue
        if service_name(p.protocol, p.src_port) and not service_name(p.protocol, p.dst_port):
            port = p.src_port
        else:
            port = p.dst_port
        counts[(p.protocol, port)] += 1
    return [{"protocol": proto, "port": port, "service": service_name(proto, port), "packets": n}
            for (proto, port), n in counts.most_common()]


def timeline(packets: list[Packet], start: float, end: float) -> list[dict]:
    """Packets and bytes per time bucket, for the traffic-over-time chart."""
    span = max(end - start, 1e-6)
    width = span / TIMELINE_BUCKETS
    buckets = [{"t": round(i * width, 3), "packets": 0, "bytes": 0} for i in range(TIMELINE_BUCKETS)]
    for p in packets:
        i = min(int((p.timestamp - start) / width), TIMELINE_BUCKETS - 1)
        buckets[i]["packets"] += 1
        buckets[i]["bytes"] += p.wire_length
    return buckets


def build_graph(packets: list[Packet], protocol: str | None = None, min_packets: int = 1) -> dict:
    """Hosts as nodes, conversations as edges weighted by packets and bytes.

    Edges are undirected: A→B and B→A traffic is one conversation.
    """
    selected = [p for p in packets if p.src_ip and p.dst_ip and (not protocol or p.protocol == protocol)]

    edges: dict[tuple[str, str], dict] = {}
    for p in selected:
        a, b = sorted((p.src_ip, p.dst_ip))
        e = edges.setdefault((a, b), {"source": a, "target": b, "packets": 0, "bytes": 0,
                                      "protocols": set(), "services": set()})
        e["packets"] += 1
        e["bytes"] += p.wire_length
        e["protocols"].add(p.protocol)
        if p.service:
            e["services"].add(p.service)

    kept = [e for e in edges.values() if e["packets"] >= min_packets]

    g = nx.Graph()
    for e in kept:
        g.add_edge(e["source"], e["target"], weight=e["packets"])

    hosts = host_table(selected)
    centrality = nx.degree_centrality(g) if g.number_of_nodes() > 1 else {}
    hub_threshold = _hub_threshold(g)

    nodes = []
    for ip in g.nodes:
        h = hosts[ip]
        nodes.append({
            "id": ip,
            "internal": h["internal"],
            "packets": h["packets_sent"] + h["packets_received"],
            "bytes": h["bytes_sent"] + h["bytes_received"],
            "degree": g.degree(ip),
            "centrality": round(centrality.get(ip, 0.0), 4),
            "hub": g.degree(ip) >= hub_threshold,
        })

    for e in kept:
        e["protocols"] = sorted(e["protocols"])
        e["services"] = sorted(e["services"])
        e["protocol"] = e["protocols"][0] if len(e["protocols"]) == 1 else "Mixed"

    return {"nodes": nodes, "edges": kept}


def _hub_threshold(g: nx.Graph) -> int:
    """A hub talks to clearly more peers than a typical host: at least 4, and top ~10%."""
    degrees = sorted((d for _, d in g.degree), reverse=True)
    if not degrees:
        return 1
    top_index = max(0, len(degrees) // 10 - 1)
    return max(4, degrees[top_index])


def conversation_filter(packets: list[Packet], ip: str | None = None, protocol: str | None = None,
                        port: int | None = None, peer: str | None = None) -> list[Packet]:
    """Packets matching the packet-list filters."""
    out = []
    for p in packets:
        if ip and ip not in (p.src_ip, p.dst_ip):
            continue
        if peer and peer not in (p.src_ip, p.dst_ip):
            continue
        if protocol and p.protocol != protocol:
            continue
        if port is not None and port not in (p.src_port, p.dst_port):
            continue
        out.append(p)
    return out
