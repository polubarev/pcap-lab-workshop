"""Read classic .pcap files and decode Ethernet, ARP, IPv4, TCP, UDP and ICMP.

The reader is written in plain Python on purpose: no Wireshark or packet-capture
driver is needed, and every header field is decoded in one readable place.

Every decoded field records its byte offset and length inside the frame, so the
UI can highlight the matching bytes in the hex view when a field is selected.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from services import service_name

# Global header magic numbers (as read little-endian from the first 4 bytes).
_MAGIC_USEC_LE = 0xA1B2C3D4
_MAGIC_USEC_BE = 0xD4C3B2A1
_MAGIC_NSEC_LE = 0xA1B23C4D
_MAGIC_NSEC_BE = 0x4D3CB2A1
_PCAPNG_MAGIC = 0x0A0D0D0A

LINKTYPE_ETHERNET = 1

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

TCP_FLAG_NAMES = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                  (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]


class PcapError(ValueError):
    """The file is not a capture this reader can open."""


@dataclass
class Field:
    name: str
    value: str
    offset: int
    length: int

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value, "offset": self.offset, "length": self.length}


@dataclass
class Layer:
    name: str
    summary: str
    offset: int
    length: int
    fields: list[Field] = field(default_factory=list)

    def add(self, name: str, value, offset: int, length: int) -> None:
        self.fields.append(Field(name, str(value), offset, length))

    def to_dict(self) -> dict:
        return {"name": self.name, "summary": self.summary, "offset": self.offset,
                "length": self.length, "fields": [f.to_dict() for f in self.fields]}


@dataclass
class Packet:
    """One captured frame, with the fields the analysis and UI need."""
    index: int
    timestamp: float
    wire_length: int
    data: bytes
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str = "Other"          # TCP, UDP, ICMP, ARP or Other
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str = ""
    payload_offset: int | None = None  # where the TCP/UDP payload starts in `data`
    layers: list[Layer] = field(default_factory=list)

    @property
    def payload(self) -> bytes:
        return b"" if self.payload_offset is None else self.data[self.payload_offset:]

    @property
    def service(self) -> str | None:
        """Well-known service of the server side, e.g. 'HTTPS' for port 443."""
        for port in (self.dst_port, self.src_port):
            name = service_name(self.protocol, port)
            if name:
                return name
        return None

    @property
    def info(self) -> str:
        """One-line summary for the packet list."""
        if self.protocol in ("TCP", "UDP"):
            text = f"{self.src_port} → {self.dst_port}"
            if self.tcp_flags:
                text += f" [{self.tcp_flags}]"
            if self.payload:
                text += f" len={len(self.payload)}"
            return text
        return self.layers[-1].summary if self.layers else ""


# ---------- file level ----------

def read_pcap(path: str | Path) -> list[Packet]:
    """Read every frame of a classic pcap file and decode its headers."""
    raw = Path(path).read_bytes()
    return parse_pcap_bytes(raw)


def parse_pcap_bytes(raw: bytes) -> list[Packet]:
    if len(raw) < 24:
        raise PcapError("File is too short to be a pcap capture.")
    magic = struct.unpack("<I", raw[:4])[0]
    if magic == _PCAPNG_MAGIC:
        raise PcapError("This is a pcapng file. Save it as 'Wireshark/tcpdump - pcap' and try again.")
    if magic in (_MAGIC_USEC_LE, _MAGIC_NSEC_LE):
        endian = "<"
    elif magic in (_MAGIC_USEC_BE, _MAGIC_NSEC_BE):
        endian = ">"
    else:
        raise PcapError("Not a pcap file (unknown magic number).")
    ts_divisor = 1_000_000_000 if magic in (_MAGIC_NSEC_LE, _MAGIC_NSEC_BE) else 1_000_000

    linktype = struct.unpack(endian + "I", raw[20:24])[0]
    if linktype != LINKTYPE_ETHERNET:
        raise PcapError(f"Only Ethernet captures are supported (link type {linktype}).")

    packets: list[Packet] = []
    offset = 24
    while offset + 16 <= len(raw):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", raw[offset:offset + 16])
        offset += 16
        frame = raw[offset:offset + incl_len]
        offset += incl_len
        if len(frame) < incl_len:
            break  # truncated last record
        pkt = Packet(index=len(packets), timestamp=ts_sec + ts_frac / ts_divisor,
                     wire_length=orig_len, data=frame)
        decode_frame(pkt)
        packets.append(pkt)
    return packets


# ---------- layer decoders ----------

def decode_frame(pkt: Packet) -> None:
    data = pkt.data
    if len(data) < 14:
        return
    eth = Layer("Ethernet II", "", 0, 14)
    eth.add("Destination", _mac(data[0:6]), 0, 6)
    eth.add("Source", _mac(data[6:12]), 6, 6)
    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = 14
    if ethertype == ETHERTYPE_VLAN and len(data) >= 18:
        eth.add("VLAN ID", struct.unpack("!H", data[14:16])[0] & 0x0FFF, 14, 2)
        ethertype = struct.unpack("!H", data[16:18])[0]
        offset = 18
        eth.length = 18
    eth.add("Type", f"0x{ethertype:04x}", offset - 2, 2)
    eth.summary = f"{_mac(data[6:12])} → {_mac(data[0:6])}"
    pkt.layers.append(eth)

    if ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(pkt, offset)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(pkt, offset)


def _decode_arp(pkt: Packet, o: int) -> None:
    d = pkt.data
    if len(d) < o + 28:
        return
    op = struct.unpack("!H", d[o + 6:o + 8])[0]
    sender_ip, target_ip = _ip(d[o + 14:o + 18]), _ip(d[o + 24:o + 28])
    layer = Layer("ARP", "", o, 28)
    layer.add("Opcode", {1: "request (1)", 2: "reply (2)"}.get(op, str(op)), o + 6, 2)
    layer.add("Sender MAC", _mac(d[o + 8:o + 14]), o + 8, 6)
    layer.add("Sender IP", sender_ip, o + 14, 4)
    layer.add("Target MAC", _mac(d[o + 18:o + 24]), o + 18, 6)
    layer.add("Target IP", target_ip, o + 24, 4)
    layer.summary = (f"Who has {target_ip}? Tell {sender_ip}" if op == 1
                     else f"{sender_ip} is at {_mac(d[o + 8:o + 14])}")
    pkt.layers.append(layer)
    pkt.protocol = "ARP"
    pkt.src_ip, pkt.dst_ip = sender_ip, target_ip


def _decode_ipv4(pkt: Packet, o: int) -> None:
    d = pkt.data
    if len(d) < o + 20:
        return
    ihl = (d[o] & 0x0F) * 4
    total_len = struct.unpack("!H", d[o + 2:o + 4])[0]
    ttl, proto = d[o + 8], d[o + 9]
    src, dst = _ip(d[o + 12:o + 16]), _ip(d[o + 16:o + 20])
    layer = Layer("IPv4", f"{src} → {dst}", o, ihl)
    layer.add("Version", d[o] >> 4, o, 1)
    layer.add("Header length", f"{ihl} bytes", o, 1)
    layer.add("Total length", total_len, o + 2, 2)
    layer.add("Identification", f"0x{struct.unpack('!H', d[o + 4:o + 6])[0]:04x}", o + 4, 2)
    layer.add("Time to live", ttl, o + 8, 1)
    layer.add("Protocol", {1: "ICMP (1)", 6: "TCP (6)", 17: "UDP (17)"}.get(proto, str(proto)), o + 9, 1)
    layer.add("Header checksum", f"0x{struct.unpack('!H', d[o + 10:o + 12])[0]:04x}", o + 10, 2)
    layer.add("Source", src, o + 12, 4)
    layer.add("Destination", dst, o + 16, 4)
    pkt.layers.append(layer)
    pkt.src_ip, pkt.dst_ip = src, dst

    l4 = o + ihl
    if proto == IP_PROTO_TCP:
        _decode_tcp(pkt, l4)
    elif proto == IP_PROTO_UDP:
        _decode_udp(pkt, l4)
    elif proto == IP_PROTO_ICMP:
        _decode_icmp(pkt, l4)


def _decode_tcp(pkt: Packet, o: int) -> None:
    d = pkt.data
    if len(d) < o + 20:
        return
    sport, dport = _u16(d, o), _u16(d, o + 2)
    seq, ack = struct.unpack("!II", d[o + 4:o + 12])
    header_len = (d[o + 12] >> 4) * 4
    flags = d[o + 13]
    flag_text = ",".join(name for bit, name in TCP_FLAG_NAMES if flags & bit)
    layer = Layer("TCP", f"{sport} → {dport} [{flag_text}]", o, header_len)
    layer.add("Source port", sport, o, 2)
    layer.add("Destination port", dport, o + 2, 2)
    layer.add("Sequence number", seq, o + 4, 4)
    layer.add("Acknowledgment number", ack, o + 8, 4)
    layer.add("Header length", f"{header_len} bytes", o + 12, 1)
    layer.add("Flags", f"0x{flags:02x} ({flag_text or 'none'})", o + 13, 1)
    layer.add("Window", _u16(d, o + 14), o + 14, 2)
    pkt.layers.append(layer)
    pkt.protocol = "TCP"
    pkt.src_port, pkt.dst_port, pkt.tcp_flags = sport, dport, flag_text
    pkt.payload_offset = min(o + header_len, len(d))


def _decode_udp(pkt: Packet, o: int) -> None:
    d = pkt.data
    if len(d) < o + 8:
        return
    sport, dport, length, checksum = struct.unpack("!HHHH", d[o:o + 8])
    layer = Layer("UDP", f"{sport} → {dport}", o, 8)
    layer.add("Source port", sport, o, 2)
    layer.add("Destination port", dport, o + 2, 2)
    layer.add("Length", length, o + 4, 2)
    layer.add("Checksum", f"0x{checksum:04x}", o + 6, 2)
    pkt.layers.append(layer)
    pkt.protocol = "UDP"
    pkt.src_port, pkt.dst_port = sport, dport
    pkt.payload_offset = o + 8


def _decode_icmp(pkt: Packet, o: int) -> None:
    d = pkt.data
    if len(d) < o + 4:
        return
    icmp_type, code = d[o], d[o + 1]
    names = {0: "Echo reply", 3: "Destination unreachable", 8: "Echo request", 11: "Time exceeded"}
    layer = Layer("ICMP", names.get(icmp_type, f"Type {icmp_type}"), o, len(d) - o)
    layer.add("Type", f"{icmp_type} ({names.get(icmp_type, 'other')})", o, 1)
    layer.add("Code", code, o + 1, 1)
    layer.add("Checksum", f"0x{struct.unpack('!H', d[o + 2:o + 4])[0]:04x}", o + 2, 2)
    pkt.layers.append(layer)
    pkt.protocol = "ICMP"


# ---------- helpers ----------

def _u16(b: bytes, offset: int) -> int:
    """Two bytes at `offset` as an unsigned 16-bit integer."""
    return int.from_bytes(b[offset:offset + 2], "little")


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)
