"""DNS decoder: the header and the question section of queries and responses."""
from __future__ import annotations

import struct

from decoders import DecodedLayer, decoder

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


@decoder(name="DNS", protocol="UDP", port=53)
def decode_dns(payload: bytes) -> DecodedLayer:
    if len(payload) < 12:
        raise ValueError("payload shorter than the 12-byte DNS header")
    tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
    is_response = bool(flags & 0x8000)

    layer = DecodedLayer("DNS")
    layer.add("Transaction ID", f"0x{tx_id:04x}", 0, 2)
    layer.add("Flags", f"0x{flags:04x} ({'response' if is_response else 'query'})", 2, 2)
    layer.add("Questions", qdcount, 4, 2)
    layer.add("Answer records", ancount, 6, 2)

    offset = 12
    names = []
    for _ in range(qdcount):
        name, end = _read_name(payload, offset)
        qtype, _qclass = struct.unpack("!HH", payload[end:end + 4])
        layer.add("Query name", name, offset, end - offset)
        layer.add("Query type", QTYPES.get(qtype, str(qtype)), end, 2)
        names.append(f"{QTYPES.get(qtype, qtype)} {name}")
        offset = end + 4

    layer.summary = ("Response: " if is_response else "Query: ") + ", ".join(names)
    return layer


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read an uncompressed DNS name; returns (name, offset after it)."""
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0:
            # Compression pointer: the name continues elsewhere; stop here for the question section.
            return ".".join(labels + ["…"]), offset + 2
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
