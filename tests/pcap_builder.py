"""Build small pcap files in memory for tests."""
from __future__ import annotations

import struct

LAN_MAC = bytes.fromhex("021a2b000001")
GW_MAC = bytes.fromhex("021a2b0000fe")


def ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return GW_MAC + LAN_MAC + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                         ip_bytes(src), ip_bytes(dst))
    return ethernet(header + payload)


def tcp(src: str, sport: int, dst: str, dport: int, flags: int = 0x02, payload: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, flags, 64240, 0, 0)
    return ipv4(src, dst, 6, header + payload)


def udp(src: str, sport: int, dst: str, dport: int, payload: bytes = b"") -> bytes:
    return ipv4(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def icmp_echo(src: str, dst: str) -> bytes:
    return ipv4(src, dst, 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping")


def arp_request(sender: str, target: str) -> bytes:
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, LAN_MAC, ip_bytes(sender), b"\x00" * 6, ip_bytes(target))
    return ethernet(body, ethertype=0x0806)


def dns_query(name: str, qid: int = 0x1234) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def pcap_bytes(frames: list[tuple[float, bytes]], big_endian: bool = False) -> bytes:
    e = ">" if big_endian else "<"
    out = struct.pack(e + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in frames:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack(e + "IIII", sec, usec, len(frame), len(frame)) + frame
    return out


def small_capture() -> list[tuple[float, bytes]]:
    """Seven packets: an HTTPS handshake start, a DNS query, ICMP, ARP and one more HTTPS packet."""
    t = 1_700_000_000.0
    return [
        (t + 0.0, tcp("10.0.0.5", 50000, "203.0.113.10", 443, flags=0x02)),
        (t + 0.1, tcp("203.0.113.10", 443, "10.0.0.5", 50000, flags=0x12)),
        (t + 0.2, tcp("10.0.0.5", 50000, "203.0.113.10", 443, flags=0x18, payload=b"x" * 100)),
        (t + 1.0, udp("10.0.0.5", 53000, "10.0.0.2", 53, dns_query("portal.example.com"))),
        (t + 2.0, icmp_echo("10.0.0.5", "10.0.0.1")),
        (t + 3.0, arp_request("10.0.0.5", "10.0.0.1")),
        (t + 4.0, tcp("10.0.0.6", 50001, "203.0.113.10", 443, flags=0x02)),
    ]
