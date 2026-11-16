"""Small shared helpers: protocol name tables, address formatting and checksums.

Nothing in this module depends on the rest of the package, so it can be imported
from every layer (readers, decoders, analysis and reports).
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

# Link types from the libpcap/pcapng registries (only Ethernet is decoded fully).
LINKTYPE_NAMES: dict[int, str] = {
    0: "Null",
    1: "Ethernet",
    101: "Raw IP",
    105: "IEEE 802.11",
    113: "Linux cooked capture",
    127: "IEEE 802.11 with radiotap",
    276: "Linux cooked capture v2",
}

ETHERTYPE_NAMES: dict[int, str] = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q VLAN",
    0x86DD: "IPv6",
    0x88A8: "802.1ad QinQ",
    0x8847: "MPLS",
    0x88CC: "LLDP",
    0x9000: "Loopback",
    0x9100: "802.1QinQ (legacy)",
    0x9200: "802.1QinQ (legacy)",
}

IP_PROTOCOL_NAMES: dict[int, str] = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    4: "IP-in-IP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    43: "Routing",
    44: "Fragment",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    60: "Destination Options",
    89: "OSPF",
    132: "SCTP",
}

ICMP_TYPE_NAMES: dict[int, str] = {
    0: "echo reply",
    3: "destination unreachable",
    4: "source quench",
    5: "redirect",
    8: "echo request",
    9: "router advertisement",
    10: "router solicitation",
    11: "time exceeded",
    12: "parameter problem",
    13: "timestamp request",
    14: "timestamp reply",
}

ICMPV6_TYPE_NAMES: dict[int, str] = {
    1: "destination unreachable",
    2: "packet too big",
    3: "time exceeded",
    4: "parameter problem",
    128: "echo request",
    129: "echo reply",
    133: "router solicitation",
    134: "router advertisement",
    135: "neighbor solicitation",
    136: "neighbor advertisement",
    137: "redirect",
}

DNS_TYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}

DNS_CLASS_NAMES: dict[int, str] = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

DNS_OPCODE_NAMES: dict[int, str] = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}

DNS_RCODE_NAMES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def ethertype_name(ethertype: int) -> str:
    """Return the human name of an EtherType, or a hex fallback."""
    return ETHERTYPE_NAMES.get(ethertype, f"0x{ethertype:04x}")


def ip_protocol_name(protocol: int) -> str:
    """Return the human name of an IP protocol number, or a numeric fallback."""
    return IP_PROTOCOL_NAMES.get(protocol, f"protocol {protocol}")


def dns_type_name(rtype: int) -> str:
    """Return the human name of a DNS record type, or ``TYPE<n>``."""
    return DNS_TYPE_NAMES.get(rtype, f"TYPE{rtype}")


def dns_class_name(rclass: int) -> str:
    """Return the human name of a DNS class, or ``CLASS<n>``."""
    return DNS_CLASS_NAMES.get(rclass, f"CLASS{rclass}")


def dns_opcode_name(opcode: int) -> str:
    """Return the human name of a DNS opcode, or ``OPCODE<n>``."""
    return DNS_OPCODE_NAMES.get(opcode, f"OPCODE{opcode}")


def dns_rcode_name(rcode: int) -> str:
    """Return the human name of a DNS response code, or ``RCODE<n>``."""
    return DNS_RCODE_NAMES.get(rcode, f"RCODE{rcode}")


def mac_to_string(raw: bytes) -> str:
    """Format six raw bytes as a colon-separated MAC address."""
    return ":".join(f"{byte:02x}" for byte in raw)


def ipv4_to_string(raw: bytes) -> str:
    """Format four raw bytes as a dotted-quad IPv4 address."""
    if len(raw) != 4:  # pragma: no cover - callers always pass the right size
        raise ValueError("IPv4 address must be 4 bytes")
    return str(ipaddress.IPv4Address(raw))


def ipv6_to_string(raw: bytes) -> str:
    """Format sixteen raw bytes as a compressed (RFC 5952) IPv6 address."""
    if len(raw) != 16:  # pragma: no cover - callers always pass the right size
        raise ValueError("IPv6 address must be 16 bytes")
    return str(ipaddress.IPv6Address(raw))


def endpoint_to_string(address: str, port: int | None) -> str:
    """Format an IP address plus optional port, bracketing IPv6 addresses."""
    if port is None:
        return address
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def internet_checksum(data: bytes) -> int:
    """Compute the 16-bit one's complement checksum used by IP and ICMP."""
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def format_bytes(value: int) -> str:
    """Format a byte count with the usual KiB/MiB suffixes."""
    if value < 1024:
        return f"{value} B"
    units = ("KiB", "MiB", "GiB", "TiB")
    scaled = float(value)
    for unit in units:
        scaled /= 1024.0
        if scaled < 1024.0:
            return f"{scaled:.1f} {unit}"
    return f"{scaled:.1f} PiB"


def format_duration(duration_ns: int) -> str:
    """Format a nanosecond duration with a readable unit."""
    if duration_ns >= 1_000_000_000:
        return f"{duration_ns / 1_000_000_000:.3f} s"
    if duration_ns >= 1_000_000:
        return f"{duration_ns / 1_000_000:.3f} ms"
    if duration_ns >= 1_000:
        return f"{duration_ns / 1_000:.3f} us"
    return f"{duration_ns} ns"


def format_packet_rate(packets_per_second: float) -> str:
    """Format a packet rate in packets per second."""
    return f"{packets_per_second:.1f} pkt/s"


def format_bit_rate(bits_per_second: float) -> str:
    """Format a bit rate with SI prefixes, which is the network convention."""
    if bits_per_second < 1_000:
        return f"{bits_per_second:.0f} bit/s"
    if bits_per_second < 1_000_000:
        return f"{bits_per_second / 1_000:.1f} kbit/s"
    if bits_per_second < 1_000_000_000:
        return f"{bits_per_second / 1_000_000:.2f} Mbit/s"
    return f"{bits_per_second / 1_000_000_000:.2f} Gbit/s"


def _utc_datetime(timestamp_ns: int) -> datetime:
    seconds, fraction_ns = divmod(timestamp_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=fraction_ns // 1000)


def format_timestamp(timestamp_ns: int, *, include_date: bool = True) -> str:
    """Format a capture timestamp in UTC, with microsecond precision."""
    moment = _utc_datetime(timestamp_ns)
    if include_date:
        return moment.strftime("%Y-%m-%d %H:%M:%S.%f") + " UTC"
    return moment.strftime("%H:%M:%S.%f")


def iso_timestamp(timestamp_ns: int) -> str:
    """Format a capture timestamp as an ISO 8601 UTC instant."""
    return _utc_datetime(timestamp_ns).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def format_count(value: int) -> str:
    """Format an integer with thousands separators."""
    return f"{value:,}"
