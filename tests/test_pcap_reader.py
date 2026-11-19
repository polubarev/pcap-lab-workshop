import pytest

from pcap_builder import pcap_bytes, small_capture
from pcap_reader import PcapError, parse_pcap_bytes, read_pcap


def test_reads_every_packet(small_pcap):
    packets = read_pcap(small_pcap)
    assert len(packets) == 7
    assert [p.protocol for p in packets] == ["TCP", "TCP", "TCP", "UDP", "ICMP", "ARP", "TCP"]


def test_tcp_fields(small_pcap):
    syn, syn_ack, data = read_pcap(small_pcap)[:3]
    assert (syn.src_ip, syn.dst_ip) == ("10.0.0.5", "203.0.113.10")
    assert syn.tcp_flags == "SYN"
    assert syn_ack.tcp_flags == "SYN,ACK"
    assert data.payload == b"x" * 100


def test_udp_fields_and_service(small_pcap):
    dns = read_pcap(small_pcap)[3]
    assert (dns.src_port, dns.dst_port) == (53000, 53)
    assert dns.service == "DNS"


def test_timestamps_are_seconds(small_pcap):
    packets = read_pcap(small_pcap)
    assert packets[3].timestamp - packets[0].timestamp == pytest.approx(1.0)


def test_arp_addresses(small_pcap):
    arp = read_pcap(small_pcap)[5]
    assert (arp.src_ip, arp.dst_ip) == ("10.0.0.5", "10.0.0.1")
    assert arp.layers[-1].summary == "Who has 10.0.0.1? Tell 10.0.0.5"


def test_field_offsets_point_at_the_right_bytes(small_pcap):
    syn = read_pcap(small_pcap)[0]
    tcp = next(layer for layer in syn.layers if layer.name == "TCP")
    dport = next(f for f in tcp.fields if f.name == "Destination port")
    assert syn.data[dport.offset:dport.offset + dport.length] == (443).to_bytes(2, "big")


def test_big_endian_file_header():
    packets = parse_pcap_bytes(pcap_bytes(small_capture(), big_endian=True))
    assert len(packets) == 7


def test_rejects_pcapng():
    with pytest.raises(PcapError, match="pcapng"):
        parse_pcap_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)


def test_rejects_other_files():
    with pytest.raises(PcapError):
        parse_pcap_bytes(b"PK\x03\x04 this is a zip file, not a capture")
