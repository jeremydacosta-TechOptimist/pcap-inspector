"""Packet decoding from the link layer up to DNS.

Decoding is deliberately tolerant: a corrupt or truncated packet never raises
out of :func:`decode_packet`.  Every layer that could be decoded is kept and
anything missing is recorded in ``notes`` (informational, such as IP fragments)
or ``errors`` (real problems, such as a truncated header).  Only Ethernet is
decoded as a link layer; other link types are reported honestly.
"""

from __future__ import annotations

import struct

from . import dns
from .errors import DnsDecodeError
from .models import (
    LINKTYPE_ETHERNET,
    ArpPacket,
    Capture,
    CapturedPacket,
    DecodedPacket,
    DnsMessage,
    EthernetHeader,
    IcmpMessage,
    Icmpv6Message,
    Ipv4Header,
    Ipv6Header,
    TcpSegment,
    UdpDatagram,
    VlanTag,
)
from .util import (
    ICMPV6_TYPE_NAMES,
    ICMP_TYPE_NAMES,
    LINKTYPE_NAMES,
    endpoint_to_string,
    ethertype_name,
    internet_checksum,
    ip_protocol_name,
    ipv4_to_string,
    ipv6_to_string,
    mac_to_string,
)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
VLAN_TPIDS = frozenset({0x8100, 0x88A8, 0x9100, 0x9200})
MAX_VLAN_TAGS = 8
MAX_IPV6_EXTENSION_HEADERS = 8
IPV6_EXTENSION_HEADERS = frozenset({0, 43, 44, 51, 60})
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
DNS_PORT = 53

TCP_FLAG_ORDER = (
    ("SYN", 0x02),
    ("FIN", 0x01),
    ("RST", 0x04),
    ("PSH", 0x08),
    ("ACK", 0x10),
    ("URG", 0x20),
    ("ECE", 0x40),
    ("CWR", 0x80),
)


def decode_capture(capture: Capture) -> list[DecodedPacket]:
    """Decode every packet of a capture, preserving the packet order."""
    return [
        decode_packet(packet, index)
        for index, packet in enumerate(capture.packets, start=1)
    ]


def decode_packet(packet: CapturedPacket, index: int) -> DecodedPacket:
    """Decode one captured packet; never raises for malformed input."""
    decoded = DecodedPacket(
        index=index,
        timestamp_ns=packet.timestamp_ns,
        captured_length=packet.captured_length,
        original_length=packet.original_length,
        interface_id=packet.interface_id,
        truncated=packet.truncated,
    )
    try:
        if packet.linktype != LINKTYPE_ETHERNET:
            name = LINKTYPE_NAMES.get(packet.linktype, "unknown")
            decoded.notes.append(
                f"link layer: link type {packet.linktype} ({name}) is not decoded; "
                "only Ethernet is supported"
            )
            return decoded
        _decode_ethernet(decoded, packet.data)
    except (struct.error, IndexError, ValueError) as exc:  # pragma: no cover - defensive
        decoded.errors.append(f"decoder: unexpected failure ({exc})")
    return decoded


def _decode_ethernet(decoded: DecodedPacket, data: bytes) -> None:
    """Decode the Ethernet header, VLAN tags and the encapsulated protocol."""
    if len(data) < 14:
        decoded.errors.append(
            f"ethernet: frame is {len(data)} bytes, shorter than the 14-byte header"
        )
        return
    decoded.ethernet = EthernetHeader(
        destination=mac_to_string(data[0:6]),
        source=mac_to_string(data[6:12]),
        ethertype=int.from_bytes(data[12:14], "big"),
    )
    offset = 14
    ethertype = decoded.ethernet.ethertype
    while ethertype in VLAN_TPIDS:
        if len(decoded.vlans) >= MAX_VLAN_TAGS:
            decoded.errors.append(
                f"vlan: more than {MAX_VLAN_TAGS} nested tags; stopped decoding"
            )
            return
        if len(data) - offset < 4:
            decoded.errors.append("vlan: truncated VLAN tag")
            decoded.truncated = True
            return
        tag_control = int.from_bytes(data[offset : offset + 2], "big")
        ethertype = int.from_bytes(data[offset + 2 : offset + 4], "big")
        decoded.vlans.append(
            VlanTag(
                pcp=tag_control >> 13,
                dei=bool(tag_control & 0x1000),
                vid=tag_control & 0x0FFF,
                ethertype=ethertype,
            )
        )
        offset += 4

    if ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(decoded, data, offset)
    elif ethertype == ETHERTYPE_IPV6:
        _decode_ipv6(decoded, data, offset)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(decoded, data, offset)
    else:
        decoded.notes.append(
            f"link layer: EtherType 0x{ethertype:04x} "
            f"({ethertype_name(ethertype)}) payload is not decoded"
        )


def _decode_arp(decoded: DecodedPacket, data: bytes, offset: int) -> None:
    """Decode an Ethernet/IPv4 ARP packet."""
    available = len(data) - offset
    if available < 8:
        decoded.errors.append(f"arp: header truncated ({available} of 8 bytes)")
        decoded.truncated = True
        return
    hardware_type, protocol_type, hardware_length, protocol_length, operation = (
        struct.unpack("!HHBBH", data[offset : offset + 8])
    )
    if hardware_type != 1 or protocol_type != ETHERTYPE_IPV4:
        decoded.notes.append(
            f"arp: unsupported address family (hardware {hardware_type}, "
            f"protocol 0x{protocol_type:04x})"
        )
        return
    if hardware_length != 6 or protocol_length != 4:
        decoded.notes.append(
            f"arp: unsupported address sizes (hardware {hardware_length}, "
            f"protocol {protocol_length})"
        )
        return
    body = offset + 8
    if len(data) - body < 20:
        decoded.errors.append(
            f"arp: addresses truncated ({len(data) - body} of 20 bytes)"
        )
        decoded.truncated = True
        return
    decoded.arp = ArpPacket(
        operation=operation,
        sender_mac=mac_to_string(data[body : body + 6]),
        sender_ip=ipv4_to_string(data[body + 6 : body + 10]),
        target_mac=mac_to_string(data[body + 10 : body + 16]),
        target_ip=ipv4_to_string(data[body + 16 : body + 20]),
    )


def _decode_ipv4(decoded: DecodedPacket, data: bytes, offset: int) -> None:
    """Decode an IPv4 header and its transport payload."""
    available = len(data) - offset
    if available < 20:
        decoded.errors.append(f"ipv4: header truncated ({available} of 20 bytes)")
        decoded.truncated = True
        return
    version_ihl = data[offset]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    if version != 4:
        decoded.errors.append(f"ipv4: unexpected version {version}")
        return
    if ihl < 5:
        decoded.errors.append(f"ipv4: invalid header length {ihl * 4} bytes")
        return
    header_length = ihl * 4
    if available < header_length:
        decoded.errors.append(
            f"ipv4: header truncated ({available} of {header_length} bytes)"
        )
        decoded.truncated = True
        return
    (
        total_length,
        identification,
        flags_field,
        time_to_live,
        protocol,
        header_checksum,
    ) = struct.unpack("!HHHBBH", data[offset + 2 : offset + 12])
    header_bytes = bytearray(data[offset : offset + header_length])
    header_bytes[10:12] = b"\x00\x00"
    computed_checksum = internet_checksum(bytes(header_bytes))
    header = Ipv4Header(
        ihl=ihl,
        dscp=data[offset + 1] >> 2,
        ecn=data[offset + 1] & 0x03,
        total_length=total_length,
        identification=identification,
        dont_fragment=bool(flags_field & 0x4000),
        more_fragments=bool(flags_field & 0x2000),
        fragment_offset=(flags_field & 0x1FFF) * 8,
        time_to_live=time_to_live,
        protocol=protocol,
        header_checksum=header_checksum,
        checksum_valid=computed_checksum == header_checksum,
        source=ipv4_to_string(data[offset + 12 : offset + 16]),
        destination=ipv4_to_string(data[offset + 16 : offset + 20]),
        options_length=header_length - 20,
    )
    decoded.ipv4 = header
    if not header.checksum_valid:
        decoded.notes.append(
            f"ipv4: header checksum mismatch (stored 0x{header_checksum:04x}, "
            f"computed 0x{computed_checksum:04x})"
        )
    if total_length < header_length:
        decoded.errors.append(
            f"ipv4: total length {total_length} is smaller than its {header_length}-byte header"
        )
        return

    declared_payload = total_length - header_length
    captured_payload = available - header_length
    if captured_payload < declared_payload:
        decoded.errors.append(
            f"ipv4: truncated payload (declared {declared_payload}, "
            f"captured {captured_payload} bytes)"
        )
        decoded.truncated = True
    payload = data[offset + header_length : offset + header_length + min(declared_payload, captured_payload)]

    if header.fragment_offset > 0:
        decoded.notes.append(
            "ipv4: non-initial fragment; the transport header is not in this packet"
        )
        return
    if header.more_fragments:
        decoded.notes.append("ipv4: fragmented datagram; the transport payload is incomplete")
    _decode_transport(decoded, payload, protocol, declared_payload)


def _decode_ipv6(decoded: DecodedPacket, data: bytes, offset: int) -> None:
    """Decode an IPv6 header, its extension header chain and the transport payload."""
    available = len(data) - offset
    if available < 40:
        decoded.errors.append(f"ipv6: header truncated ({available} of 40 bytes)")
        decoded.truncated = True
        return
    first_word = int.from_bytes(data[offset : offset + 4], "big")
    version = (first_word >> 28) & 0x0F
    if version != 6:
        decoded.errors.append(f"ipv6: unexpected version {version}")
        return
    payload_length, next_header, hop_limit = struct.unpack(
        "!HBB", data[offset + 4 : offset + 8]
    )
    header = Ipv6Header(
        traffic_class=(first_word >> 20) & 0xFF,
        flow_label=first_word & 0xFFFFF,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        source=ipv6_to_string(data[offset + 8 : offset + 24]),
        destination=ipv6_to_string(data[offset + 24 : offset + 40]),
    )
    decoded.ipv6 = header

    captured_payload = available - 40
    if captured_payload < payload_length:
        decoded.errors.append(
            f"ipv6: truncated payload (declared {payload_length}, "
            f"captured {captured_payload} bytes)"
        )
        decoded.truncated = True
    payload_end = offset + 40 + min(payload_length, captured_payload)
    cursor = offset + 40
    current_header = next_header
    extension_headers: list[int] = []

    for _ in range(MAX_IPV6_EXTENSION_HEADERS):
        if current_header not in IPV6_EXTENSION_HEADERS:
            break
        if cursor + 2 > payload_end:
            decoded.errors.append("ipv6: truncated extension header")
            decoded.truncated = True
            break
        following_header = data[cursor]
        if current_header == 44:
            extension_length = 8
        elif current_header == 51:
            extension_length = (data[cursor + 1] + 2) * 4
        else:
            extension_length = (data[cursor + 1] + 1) * 8
        extension_headers.append(current_header)
        if cursor + extension_length > payload_end:
            decoded.errors.append("ipv6: truncated extension header")
            decoded.truncated = True
            cursor = payload_end
            break
        cursor += extension_length
        current_header = following_header
    else:
        decoded.notes.append("ipv6: stopped after too many extension headers")

    header.extension_headers = extension_headers
    header.transport_next_header = current_header
    if cursor > payload_end:
        cursor = payload_end
    payload = data[cursor:payload_end]
    _decode_transport(decoded, payload, current_header, len(payload))


def _decode_transport(
    decoded: DecodedPacket, payload: bytes, protocol: int, declared_payload: int
) -> None:
    """Decode TCP, UDP, ICMP or ICMPv6; other protocols get an honest note."""
    if protocol == IPPROTO_TCP:
        _decode_tcp(decoded, payload, declared_payload)
    elif protocol == IPPROTO_UDP:
        _decode_udp(decoded, payload, declared_payload)
    elif protocol == IPPROTO_ICMP:
        _decode_icmp(decoded, payload)
    elif protocol == IPPROTO_ICMPV6:
        _decode_icmpv6(decoded, payload)
    else:
        decoded.notes.append(
            f"ip: protocol {protocol} ({ip_protocol_name(protocol)}) payload is not decoded"
        )


def _decode_tcp(decoded: DecodedPacket, payload: bytes, declared_payload: int) -> None:
    """Decode a TCP segment."""
    if len(payload) < 20:
        decoded.errors.append(f"tcp: header truncated ({len(payload)} of 20 bytes)")
        decoded.truncated = True
        return
    source_port, destination_port, sequence, acknowledgement = struct.unpack(
        "!HHII", payload[:12]
    )
    data_offset = payload[12] >> 4
    if data_offset < 5:
        decoded.errors.append(f"tcp: invalid data offset {data_offset * 4} bytes")
        return
    header_length = data_offset * 4
    if len(payload) < header_length:
        decoded.errors.append(
            f"tcp: header truncated ({len(payload)} of {header_length} bytes)"
        )
        decoded.truncated = True
        return
    flags_byte = payload[13]
    flags = [name for name, bit in TCP_FLAG_ORDER if flags_byte & bit]
    window, checksum, urgent_pointer = struct.unpack("!HHH", payload[14:20])
    declared_tcp_payload = max(0, declared_payload - header_length)
    captured_tcp_payload = max(0, len(payload) - header_length)
    payload_length = min(declared_tcp_payload, captured_tcp_payload)
    if captured_tcp_payload < declared_tcp_payload:
        decoded.notes.append(
            f"tcp: payload incomplete (declared {declared_tcp_payload}, "
            f"captured {captured_tcp_payload} bytes)"
        )
    decoded.tcp = TcpSegment(
        source_port=source_port,
        destination_port=destination_port,
        sequence=sequence,
        acknowledgement=acknowledgement,
        header_length=header_length,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent_pointer=urgent_pointer,
        payload_length=payload_length,
    )


def _decode_udp(decoded: DecodedPacket, payload: bytes, declared_payload: int) -> None:
    """Decode a UDP datagram and, on port 53, its DNS payload."""
    if len(payload) < 8:
        decoded.errors.append(f"udp: header truncated ({len(payload)} of 8 bytes)")
        decoded.truncated = True
        return
    source_port, destination_port, length, checksum = struct.unpack("!HHHH", payload[:8])
    if length < 8:
        decoded.errors.append(f"udp: invalid length field {length}")
        return
    declared_udp_payload = length - 8
    captured_udp_payload = len(payload) - 8
    payload_length = min(declared_udp_payload, captured_udp_payload)
    if captured_udp_payload < declared_udp_payload:
        decoded.notes.append(
            f"udp: payload incomplete (declared {declared_udp_payload}, "
            f"captured {captured_udp_payload} bytes)"
        )
    elif declared_payload > length:
        decoded.notes.append(
            f"udp: datagram length {length} is smaller than the IP payload {declared_payload}"
        )
    decoded.udp = UdpDatagram(
        source_port=source_port,
        destination_port=destination_port,
        length=length,
        checksum=checksum,
        payload_length=payload_length,
    )
    if DNS_PORT not in (source_port, destination_port):
        return
    dns_payload = payload[8 : 8 + payload_length]
    try:
        decoded.dns = dns.decode_message(dns_payload)
    except DnsDecodeError as exc:
        decoded.errors.append(f"dns: {exc}")


def _decode_icmp(decoded: DecodedPacket, payload: bytes) -> None:
    """Decode an ICMP message, including echo request/reply identifiers."""
    if len(payload) < 4:
        decoded.errors.append(f"icmp: header truncated ({len(payload)} of 4 bytes)")
        decoded.truncated = True
        return
    icmp_type, code, checksum = struct.unpack("!BBH", payload[:4])
    echo_id: int | None = None
    echo_sequence: int | None = None
    if icmp_type in (0, 8) and len(payload) >= 8:
        echo_id, echo_sequence = struct.unpack("!HH", payload[4:8])
    if len(payload) < 8:
        decoded.notes.append(f"icmp: message is only {len(payload)} bytes long")
    decoded.icmp = IcmpMessage(
        type=icmp_type,
        code=code,
        checksum=checksum,
        type_name=ICMP_TYPE_NAMES.get(icmp_type, f"type {icmp_type}"),
        echo_id=echo_id,
        echo_sequence=echo_sequence,
        payload_length=max(0, len(payload) - 8),
    )


def _decode_icmpv6(decoded: DecodedPacket, payload: bytes) -> None:
    """Decode an ICMPv6 message, including echo request/reply identifiers."""
    if len(payload) < 4:
        decoded.errors.append(f"icmpv6: header truncated ({len(payload)} of 4 bytes)")
        decoded.truncated = True
        return
    icmp_type, code, checksum = struct.unpack("!BBH", payload[:4])
    echo_id: int | None = None
    echo_sequence: int | None = None
    if icmp_type in (128, 129) and len(payload) >= 8:
        echo_id, echo_sequence = struct.unpack("!HH", payload[4:8])
    if len(payload) < 8:
        decoded.notes.append(f"icmpv6: message is only {len(payload)} bytes long")
    decoded.icmpv6 = Icmpv6Message(
        type=icmp_type,
        code=code,
        checksum=checksum,
        type_name=ICMPV6_TYPE_NAMES.get(icmp_type, f"type {icmp_type}"),
        echo_id=echo_id,
        echo_sequence=echo_sequence,
        payload_length=max(0, len(payload) - 8),
    )


def _describe_dns(packet: DecodedPacket) -> str:
    """Return a one-line description of a decoded DNS packet."""
    message: DnsMessage = packet.dns  # type: ignore[assignment]
    question = message.questions[0] if message.questions else None
    transport = packet.transport_protocol or "UDP"
    endpoints = (
        f"{transport} "
        f"{endpoint_to_string(packet.source_ip or '?', packet.source_port)} -> "
        f"{endpoint_to_string(packet.destination_ip or '?', packet.destination_port)}"
    )
    if question is not None:
        subject = f"{question.name} {question.qtype_name}"
    else:
        subject = "unknown question"
    if message.is_response:
        return (
            f"DNS response {subject} rcode={message.rcode_name} "
            f"answers={len(message.answers)} ({endpoints})"
        )
    return f"DNS query {subject} ({endpoints})"


def describe_packet(packet: DecodedPacket) -> str:
    """Return a compact one-line human description of a decoded packet."""
    vlan_prefix = ""
    if packet.vlans:
        vlan_prefix = "VLAN " + "/".join(str(tag.vid) for tag in packet.vlans) + ": "

    if packet.arp is not None:
        arp = packet.arp
        if arp.operation == 1:
            body = f"ARP request who-has {arp.target_ip} tell {arp.sender_ip}"
        elif arp.operation == 2:
            body = f"ARP reply {arp.sender_ip} is-at {arp.sender_mac}"
        else:
            body = (
                f"ARP {arp.operation_name} {arp.sender_ip} -> {arp.target_ip}"
            )
    elif packet.dns is not None:
        body = _describe_dns(packet)
    elif packet.tcp is not None:
        tcp = packet.tcp
        body = (
            f"TCP "
            f"{endpoint_to_string(packet.source_ip or '?', tcp.source_port)} -> "
            f"{endpoint_to_string(packet.destination_ip or '?', tcp.destination_port)} "
            f"[{tcp.flags_text}] seq={tcp.sequence} ack={tcp.acknowledgement} "
            f"len={tcp.payload_length}"
        )
    elif packet.udp is not None:
        udp = packet.udp
        body = (
            f"UDP "
            f"{endpoint_to_string(packet.source_ip or '?', udp.source_port)} -> "
            f"{endpoint_to_string(packet.destination_ip or '?', udp.destination_port)} "
            f"len={udp.payload_length}"
        )
    elif packet.icmp is not None:
        icmp = packet.icmp
        detail = f"ICMP {icmp.type_name}"
        if icmp.echo_id is not None:
            detail += f" id={icmp.echo_id} seq={icmp.echo_sequence}"
        body = (
            f"{detail} {packet.source_ip or '?'} -> {packet.destination_ip or '?'}"
        )
    elif packet.icmpv6 is not None:
        icmpv6 = packet.icmpv6
        detail = f"ICMPv6 {icmpv6.type_name}"
        if icmpv6.echo_id is not None:
            detail += f" id={icmpv6.echo_id} seq={icmpv6.echo_sequence}"
        body = (
            f"{detail} {packet.source_ip or '?'} -> {packet.destination_ip or '?'}"
        )
    elif packet.ethernet is not None:
        body = (
            f"Ethernet {packet.ethernet.source} -> {packet.ethernet.destination} "
            f"EtherType 0x{packet.ethernet.ethertype:04x} "
            f"({packet.ethernet.ethertype_name})"
        )
    else:
        body = "undecodable frame"
        if packet.errors:
            body += f" ({packet.errors[0]})"

    if packet.truncated:
        body += " [truncated]"
    return vlan_prefix + body
