import io
import struct

from app import app
from hostnames import hostname_for
from pcap_builder import ip_bytes, pcap_bytes, udp
from pcap_reader import parse_pcap_bytes


def dns_answer(name: str, address: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return (struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + qname + struct.pack("!HH", 1, 1)
            + struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + ip_bytes(address))


def capture_with_answer():
    return pcap_bytes([(0.0, udp("10.0.0.2", 53, "10.0.0.5", 53000, dns_answer("portal.example.com", "203.0.113.10")))])


def test_name_from_dns_answer():
    packets = parse_pcap_bytes(capture_with_answer())
    assert hostname_for(packets, "203.0.113.10") == "portal.example.com"
    assert hostname_for(packets, "10.0.0.5") is None


def test_graph_nodes_carry_names():
    client = app.test_client()
    capture = client.post("/api/captures", data={"file": (io.BytesIO(capture_with_answer()), "dns.pcap")},
                          content_type="multipart/form-data").get_json()
    graph = client.get(f"/api/captures/{capture['id']}/graph").get_json()
    names = {n["id"]: n["name"] for n in graph["nodes"]}
    assert names["10.0.0.2"] is None


def test_export_csv(small_pcap):
    client = app.test_client()
    capture = client.post("/api/captures", data={"file": (io.BytesIO(small_pcap.read_bytes()), "small.pcap")},
                          content_type="multipart/form-data").get_json()
    response = client.get(f"/api/captures/{capture['id']}/export?filename=test-conversations.csv")
    assert response.status_code == 200
    lines = response.data.decode().splitlines()
    assert lines[0] == "host_a,host_b,packets,bytes,protocols,services"
    assert len(lines) == 5
