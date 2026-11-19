import decoders
from decoders.dns import decode_dns
from pcap_builder import dns_query, pcap_bytes, udp
from pcap_reader import parse_pcap_bytes


def test_dns_query_fields():
    layer = decode_dns(dns_query("portal.example.com", qid=0xBEEF))
    fields = {name: value for name, value, _, _ in layer.fields}
    assert fields["Transaction ID"] == "0xbeef"
    assert fields["Query name"] == "portal.example.com"
    assert fields["Query type"] == "A"
    assert layer.summary == "Query: A portal.example.com"


def test_decoded_offsets_are_frame_offsets():
    packet = parse_pcap_bytes(pcap_bytes([(0.0, udp("10.0.0.5", 53000, "10.0.0.2", 53, dns_query("a.example")))]))[0]
    layer, error = decoders.decode_application(packet)
    assert error is None
    tx = next(f for f in layer.fields if f.name == "Transaction ID")
    assert tx.offset == packet.payload_offset
    assert packet.data[tx.offset:tx.offset + 2] == b"\x12\x34"


def test_malformed_payload_reports_an_error():
    packet = parse_pcap_bytes(pcap_bytes([(0.0, udp("10.0.0.5", 53000, "10.0.0.2", 53, b"\x00\x01"))]))[0]
    layer, error = decoders.decode_application(packet)
    assert layer is None
    assert error.startswith("DNS:")


def test_no_decoder_for_unknown_ports():
    packet = parse_pcap_bytes(pcap_bytes([(0.0, udp("10.0.0.5", 40000, "10.0.0.9", 9999, b"hello"))]))[0]
    assert decoders.decode_application(packet) == (None, None)


def test_registry_lists_dns():
    assert {"name": "DNS", "protocol": "UDP", "port": 53} in decoders.registered()
