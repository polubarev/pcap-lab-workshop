"""Well-known ports and the services that usually run on them."""
from __future__ import annotations

WELL_KNOWN = {
    ("TCP", 20): "FTP data", ("TCP", 21): "FTP", ("TCP", 22): "SSH", ("TCP", 23): "Telnet",
    ("TCP", 25): "SMTP", ("TCP", 53): "DNS", ("UDP", 53): "DNS", ("UDP", 67): "DHCP",
    ("UDP", 68): "DHCP", ("UDP", 69): "TFTP", ("TCP", 80): "HTTP", ("UDP", 123): "NTP",
    ("TCP", 110): "POP3", ("TCP", 143): "IMAP", ("UDP", 161): "SNMP", ("TCP", 389): "LDAP",
    ("TCP", 443): "HTTPS", ("UDP", 443): "QUIC", ("TCP", 445): "SMB", ("UDP", 514): "Syslog",
    ("TCP", 993): "IMAPS", ("TCP", 1883): "MQTT", ("TCP", 3306): "MySQL", ("TCP", 3389): "RDP",
    ("UDP", 5353): "mDNS", ("TCP", 5432): "PostgreSQL", ("TCP", 8080): "HTTP-alt",
}


def service_name(protocol: str, port: int | None) -> str | None:
    if port is None:
        return None
    return WELL_KNOWN.get((protocol, port))
