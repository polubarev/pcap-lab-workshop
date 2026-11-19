from analysis import build_graph, conversation_filter, is_internal, summarize
from pcap_reader import read_pcap


def test_summary_totals(small_pcap):
    summary = summarize(read_pcap(small_pcap))
    assert summary["packets"] == 7
    assert summary["hosts"] == 5
    assert summary["duration"] == 4.0
    assert summary["protocols"] == {"TCP": 4, "UDP": 1, "ICMP": 1, "ARP": 1}


def test_top_ports_include_dns(small_pcap):
    ports = summarize(read_pcap(small_pcap))["top_ports"]
    assert {"protocol": "UDP", "port": 53, "service": "DNS", "packets": 1} in ports
    assert sum(p["packets"] for p in ports) == 5   # every TCP and UDP packet is counted once


def test_timeline_counts_every_packet(small_pcap):
    timeline = summarize(read_pcap(small_pcap))["timeline"]
    assert sum(b["packets"] for b in timeline) == 7


def test_internal_addresses():
    assert is_internal("10.20.0.5")
    assert is_internal("192.168.1.1")
    assert not is_internal("203.0.113.10")   # documentation range, still external
    assert not is_internal("8.8.8.8")


def test_graph_merges_both_directions(small_pcap):
    graph = build_graph(read_pcap(small_pcap))
    edge = next(e for e in graph["edges"] if {e["source"], e["target"]} == {"10.0.0.5", "203.0.113.10"})
    assert edge["packets"] == 3
    assert edge["protocols"] == ["TCP"]
    assert len(graph["nodes"]) == 5


def test_graph_edge_services(small_pcap):
    graph = build_graph(read_pcap(small_pcap))
    dns_edge = next(e for e in graph["edges"] if {e["source"], e["target"]} == {"10.0.0.5", "10.0.0.2"})
    assert dns_edge["services"] == ["DNS"]


def test_graph_filters(small_pcap):
    packets = read_pcap(small_pcap)
    tcp_only = build_graph(packets, protocol="TCP")
    assert {n["id"] for n in tcp_only["nodes"]} == {"10.0.0.5", "10.0.0.6", "203.0.113.10"}
    busy = build_graph(packets, min_packets=3)
    assert [(e["source"], e["target"]) for e in busy["edges"]] == [("10.0.0.5", "203.0.113.10")]


def test_packet_filters(small_pcap):
    packets = read_pcap(small_pcap)
    assert len(conversation_filter(packets, ip="10.0.0.6")) == 1
    assert len(conversation_filter(packets, port=53)) == 1
    assert len(conversation_filter(packets, ip="10.0.0.5", peer="203.0.113.10")) == 3
