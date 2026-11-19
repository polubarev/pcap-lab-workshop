"""Host names learned from DNS answers in the capture."""
from __future__ import annotations

import struct

from pcap_reader import Packet


def hostname_for(packets: list[Packet], ip: str) -> str | None:
    """The DNS name that resolved to `ip`, if the capture contains such an answer."""
    for p in packets:
        if p.protocol != "UDP" or p.src_port != 53 or not p.payload:
            continue
        for name, address in _a_records(p.payload):
            if address == ip:
                return name
    return None


def _a_records(message: bytes) -> list[tuple[str, str]]:
    """(name, IPv4 address) for every A record in the answer section."""
    if len(message) < 12:
        return []
    _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", message[:12])
    if not flags & 0x8000:
        return []
    offset = 12
    question_name = ""
    for _ in range(qdcount):
        question_name, offset = _read_name(message, offset)
        offset += 4
    records = []
    for _ in range(ancount):
        name, offset = _read_name(message, offset)
        rtype, _, _, rdlength = struct.unpack("!HHIH", message[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            records.append((name or question_name, ".".join(str(b) for b in message[offset:offset + 4])))
        offset += rdlength
    return records


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = message[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0:
            pointer = struct.unpack("!H", message[offset:offset + 2])[0] & 0x3FFF
            name, _ = _read_name(message, pointer)
            return ".".join(labels + [name]), offset + 2
        labels.append(message[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
