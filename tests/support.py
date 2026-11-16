"""Handcrafted capture and packet fixtures for the pcapkit test suite.

Everything here is built directly with :mod:`struct` and :mod:`socket` so the
tests do not depend on the library's own writers when checking the readers and
decoders.  Timestamps and identifiers are fixed, which keeps the suite
deterministic.
"""

from __future__ import annotations

import socket
import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
TPID_8021Q = 0x8100
TPID_8021AD = 0x88A8


def checksum(data: bytes) -> int:
    """Independent 16-bit one's complement checksum implementation."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(text: str) -> bytes:
    """Convert a colon-separated MAC address to bytes."""
    return bytes.fromhex(text.replace(":", ""))


def ip4(text: str) -> bytes:
    """Convert an IPv4 address to bytes."""
    return socket.inet_pton(socket.AF_INET, text)


def ip6(text: str) -> bytes:
    """Convert an IPv6 address to bytes."""
    return socket.inet_pton(socket.AF_INET6, text)


# ---------------------------------------------------------------------------
# Classic pcap fixtures
# ---------------------------------------------------------------------------


def pcap_bytes(
    records: list[tuple[int, int, bytes, int]],
    *,
    endian: str = "<",
    nanosecond: bool = False,
    linktype: int = 1,
    snaplen: int = 65535,
    version: tuple[int, int] = (2, 4),
) -> bytes:
    """Build a classic pcap file.

    ``records`` contains ``(timestamp_seconds, timestamp_fraction, data,
    original_length)`` tuples; the fraction is in microseconds, or nanoseconds
    when ``nanosecond`` is true.
    """
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    buffer = bytearray(struct.pack(endian + "I", magic))
    buffer += struct.pack(endian + "HHiIII", version[0], version[1], 0, 0, snaplen, linktype)
    for seconds, fraction, data, original_length in records:
        buffer += struct.pack(endian + "IIII", seconds, fraction, len(data), original_length)
        buffer += data
    return bytes(buffer)


def pcap_record(seconds: int, fraction: int, data: bytes, original_length: int | None = None) -> tuple[int, int, bytes, int]:
    """Build one record tuple for :func:`pcap_bytes`."""
    return (seconds, fraction, data, len(data) if original_length is None else original_length)


# ---------------------------------------------------------------------------
# pcapng fixtures
# ---------------------------------------------------------------------------


def pcapng_block(block_type: int, body: bytes, *, endian: str = "<") -> bytes:
    """Build a generic pcapng block with correct padding and length fields."""
    padded = body + b"\x00" * ((4 - len(body) % 4) % 4)
    total_length = 12 + len(padded)
    return (
        struct.pack(endian + "II", block_type, total_length)
        + padded
        + struct.pack(endian + "I", total_length)
    )


def pcapng_options(options: dict[int, bytes], *, endian: str = "<") -> bytes:
    """Encode a pcapng option list."""
    encoded = b""
    for code, value in options.items():
        encoded += struct.pack(endian + "HH", code, len(value))
        encoded += value + b"\x00" * ((4 - len(value) % 4) % 4)
    return encoded + struct.pack(endian + "HH", 0, 0)


def pcapng_shb(*, endian: str = "<", version: tuple[int, int] = (1, 0)) -> bytes:
    """Build a Section Header Block."""
    body = (
        struct.pack(endian + "I", 0x1A2B3C4D)
        + struct.pack(endian + "HH", version[0], version[1])
        + struct.pack(endian + "q", -1)
    )
    return pcapng_block(0x0A0D0D0A, body, endian=endian)


def pcapng_idb(
    *,
    endian: str = "<",
    linktype: int = 1,
    snaplen: int = 65535,
    options: dict[int, bytes] | None = None,
) -> bytes:
    """Build an Interface Description Block."""
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    body += pcapng_options(options or {}, endian=endian)
    return pcapng_block(1, body, endian=endian)


def pcapng_epb(
    interface_id: int,
    timestamp_units: int,
    packet: bytes,
    *,
    endian: str = "<",
    original_length: int | None = None,
    captured_length: int | None = None,
) -> bytes:
    """Build an Enhanced Packet Block."""
    captured = len(packet) if captured_length is None else captured_length
    original = len(packet) if original_length is None else original_length
    body = struct.pack(
        endian + "IIIII",
        interface_id,
        (timestamp_units >> 32) & 0xFFFFFFFF,
        timestamp_units & 0xFFFFFFFF,
        captured,
        original,
    )
    body += packet + b"\x00" * ((4 - len(packet) % 4) % 4)
    return pcapng_block(6, body, endian=endian)


# ---------------------------------------------------------------------------
# Packet fixtures
# ---------------------------------------------------------------------------


def ethernet(
    payload: bytes,
    *,
    destination: str = "02:00:00:00:00:02",
    source: str = "02:00:00:00:00:01",
    ethertype: int = ETHERTYPE_IPV4,
) -> bytes:
    """Build an untagged Ethernet II frame."""
    return mac(destination) + mac(source) + struct.pack("!H", ethertype) + payload


def vlan_frame(
    payload: bytes,
    tags: list[tuple[int, int, int]],
    *,
    destination: str = "02:00:00:00:00:02",
    source: str = "02:00:00:00:00:01",
    ethertype: int = ETHERTYPE_IPV4,
) -> bytes:
    """Build an Ethernet frame with one or more stacked VLAN tags."""
    header = mac(destination) + mac(source)
    for tpid, pcp, vid in tags:
        header += struct.pack("!HH", tpid, (pcp << 13) | vid)
    header += struct.pack("!H", ethertype)
    return header + payload


def arp_packet(
    *,
    operation: int = 1,
    sender_mac: str = "02:00:00:00:00:01",
    sender_ip: str = "192.0.2.10",
    target_mac: str = "00:00:00:00:00:00",
    target_ip: str = "192.0.2.20",
) -> bytes:
    """Build an Ethernet/IPv4 ARP body."""
    return (
        struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, operation)
        + mac(sender_mac)
        + ip4(sender_ip)
        + mac(target_mac)
        + ip4(target_ip)
    )


def ipv4_packet(
    payload: bytes,
    *,
    source: str = "192.0.2.10",
    destination: str = "198.51.100.53",
    protocol: int = 17,
    time_to_live: int = 64,
    flags: int = 0x4000,
    fragment_offset: int = 0,
    identification: int = 1,
    checksum_value: int | None = None,
) -> bytes:
    """Build an IPv4 packet; ``checksum_value`` forces a (possibly bad) checksum."""
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        identification,
        flags | (fragment_offset // 8),
        time_to_live,
        protocol,
        0,
        ip4(source),
        ip4(destination),
    )
    if checksum_value is None:
        checksum_value = checksum(header)
    header = header[:10] + struct.pack("!H", checksum_value) + header[12:]
    return header + payload


def ipv6_packet(
    payload: bytes,
    *,
    source: str = "2001:db8::10",
    destination: str = "2001:db8::20",
    next_header: int = 17,
    hop_limit: int = 64,
) -> bytes:
    """Build an IPv6 packet without extension headers."""
    first_word = 6 << 28
    header = (
        struct.pack("!IHBB", first_word, len(payload), next_header, hop_limit)
        + ip6(source)
        + ip6(destination)
    )
    return header + payload


def _pseudo_header(source: str, destination: str, protocol: int, length: int, ip_version: int) -> bytes:
    """Build the pseudo header used by UDP/TCP/ICMPv6 checksums."""
    if ip_version == 4:
        return ip4(source) + ip4(destination) + struct.pack("!BBH", 0, protocol, length)
    return ip6(source) + ip6(destination) + struct.pack("!I3xB", length, protocol)


def udp_datagram(
    payload: bytes,
    *,
    source: str = "192.0.2.10",
    destination: str = "198.51.100.53",
    source_port: int = 49152,
    destination_port: int = 53,
    ip_version: int = 4,
) -> bytes:
    """Build a UDP datagram with a correct checksum."""
    length = 8 + len(payload)
    base = struct.pack("!HHHH", source_port, destination_port, length, 0)
    value = checksum(_pseudo_header(source, destination, 17, length, ip_version) + base + payload)
    if value == 0:
        value = 0xFFFF
    return struct.pack("!HHHH", source_port, destination_port, length, value) + payload


def tcp_segment(
    flags: list[str],
    payload: bytes = b"",
    *,
    source: str = "192.0.2.10",
    destination: str = "198.51.100.80",
    source_port: int = 49876,
    destination_port: int = 80,
    sequence: int = 1_000_000,
    acknowledgement: int = 0,
    window: int = 64240,
    ip_version: int = 4,
) -> bytes:
    """Build a TCP segment with a correct checksum."""
    bits = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10, "URG": 0x20}
    flag_byte = 0
    for flag in flags:
        flag_byte |= bits[flag]
    header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flag_byte,
        window,
        0,
        0,
    )
    value = checksum(
        _pseudo_header(source, destination, 6, len(header) + len(payload), ip_version)
        + header
        + payload
    )
    header = header[:16] + struct.pack("!H", value) + header[18:]
    return header + payload


def icmp_echo(
    *,
    identifier: int = 1,
    sequence: int = 1,
    request: bool = True,
    payload: bytes = b"0123456789abcdef",
) -> bytes:
    """Build an ICMPv4 echo request or reply."""
    header = struct.pack("!BBHHH", 8 if request else 0, 0, 0, identifier, sequence)
    value = checksum(header + payload)
    return header[:2] + struct.pack("!H", value) + header[4:] + payload


def icmpv6_echo(
    *,
    source: str = "2001:db8::10",
    destination: str = "2001:db8::20",
    identifier: int = 2,
    sequence: int = 1,
    request: bool = True,
    payload: bytes = b"0123456789abcdef",
) -> bytes:
    """Build an ICMPv6 echo request or reply."""
    header = struct.pack("!BBHHH", 128 if request else 129, 0, 0, identifier, sequence)
    value = checksum(
        _pseudo_header(source, destination, 58, len(header) + len(payload), 6)
        + header
        + payload
    )
    return header[:2] + struct.pack("!H", value) + header[4:] + payload


# ---------------------------------------------------------------------------
# DNS fixtures
# ---------------------------------------------------------------------------


def dns_name(name: str) -> bytes:
    """Encode a DNS name as length-prefixed labels."""
    encoded = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("ascii")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def dns_query(
    name: str,
    query_type: int = 1,
    *,
    transaction_id: int = 0x1234,
    recursion_desired: bool = True,
) -> bytes:
    """Build a DNS query message."""
    flags = 0x0100 if recursion_desired else 0
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    return header + dns_name(name) + struct.pack("!HH", query_type, 1)


def dns_response(
    name: str,
    query_type: int,
    answers: list[tuple[bytes, int, int, bytes]],
    *,
    transaction_id: int = 0x1234,
    rcode: int = 0,
    question: bytes | None = None,
) -> bytes:
    """Build a DNS response; answers are ``(encoded_name, type, ttl, rdata)``."""
    flags = 0x8180 | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, len(answers), 0, 0)
    encoded_question = (
        dns_name(name) if question is None else question
    ) + struct.pack("!HH", query_type, 1)
    body = b""
    for encoded_name, record_type, ttl, rdata in answers:
        body += encoded_name + struct.pack("!HHIH", record_type, 1, ttl, len(rdata)) + rdata
    return header + encoded_question + body


QUESTION_POINTER = b"\xC0\x0C"
