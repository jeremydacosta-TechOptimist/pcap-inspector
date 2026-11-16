"""Data models shared by the readers, decoders, analysis and reporting layers.

The classes in this module are intentionally small data holders.  Raw capture
data lives in :class:`CapturedPacket`; decoded protocol fields live in one small
class per layer so that consumers can pick exactly what they need.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .util import (
    dns_class_name,
    dns_opcode_name,
    dns_rcode_name,
    dns_type_name,
    ethertype_name,
    ip_protocol_name,
)

LINKTYPE_ETHERNET = 1


@dataclass(frozen=True)
class InterfaceInfo:
    """Metadata for one capture interface (one link type and snaplen)."""

    index: int
    linktype: int
    snaplen: int
    name: str = ""
    description: str = ""
    timestamp_resolution: int = 6  # decimal exponent: 6 means microseconds
    timestamp_resolution_binary: bool = False
    timestamp_offset_ns: int = 0

    @property
    def linktype_display(self) -> str:
        """Return the link type as a readable string with its number."""
        from .util import LINKTYPE_NAMES

        name = LINKTYPE_NAMES.get(self.linktype, "unknown")
        return f"{name} ({self.linktype})"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "index": self.index,
            "linktype": self.linktype,
            "linktype_name": self.linktype_display,
            "snaplen": self.snaplen,
            "name": self.name,
            "description": self.description,
            "timestamp_resolution": self.timestamp_resolution,
            "timestamp_resolution_binary": self.timestamp_resolution_binary,
            "timestamp_offset_ns": self.timestamp_offset_ns,
        }


@dataclass(frozen=True)
class CapturedPacket:
    """One timestamped frame exactly as stored in the capture file."""

    timestamp_ns: int
    data: bytes
    original_length: int
    interface_id: int = 0
    truncated: bool = False
    linktype: int = 1

    @property
    def captured_length(self) -> int:
        """Return the number of bytes actually stored in the capture."""
        return len(self.data)


@dataclass
class Capture:
    """A parsed capture file: packets plus the format metadata."""

    source: str
    format: str
    byte_order: str
    version: str
    snaplen: int
    linktype: int
    packets: list[CapturedPacket]
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def linktype_display(self) -> str:
        """Return the capture link type as a readable string with its number."""
        from .util import LINKTYPE_NAMES

        name = LINKTYPE_NAMES.get(self.linktype, "unknown")
        return f"{name} ({self.linktype})"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the capture metadata."""
        return {
            "source": self.source,
            "format": self.format,
            "byte_order": self.byte_order,
            "version": self.version,
            "snaplen": self.snaplen,
            "linktype": self.linktype,
            "linktype_name": self.linktype_display,
            "interfaces": [interface.to_dict() for interface in self.interfaces],
            "warnings": list(self.warnings),
            "packets": len(self.packets),
        }


@dataclass
class EthernetHeader:
    """The 14-byte Ethernet II header."""

    destination: str
    source: str
    ethertype: int

    @property
    def ethertype_name(self) -> str:
        """Return the EtherType as a readable name."""
        return ethertype_name(self.ethertype)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "destination": self.destination,
            "source": self.source,
            "ethertype": self.ethertype,
            "ethertype_name": self.ethertype_name,
        }


@dataclass
class VlanTag:
    """One 802.1Q (or 802.1ad) VLAN tag."""

    pcp: int
    dei: bool
    vid: int
    ethertype: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "pcp": self.pcp,
            "dei": self.dei,
            "vid": self.vid,
            "ethertype": self.ethertype,
            "ethertype_name": ethertype_name(self.ethertype),
        }


@dataclass
class ArpPacket:
    """An ARP packet for the common Ethernet/IPv4 case."""

    operation: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def operation_name(self) -> str:
        """Return the ARP operation as ``request``/``reply`` or a number."""
        return {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"}.get(
            self.operation, f"operation {self.operation}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "operation": self.operation,
            "operation_name": self.operation_name,
            "sender_mac": self.sender_mac,
            "sender_ip": self.sender_ip,
            "target_mac": self.target_mac,
            "target_ip": self.target_ip,
        }


@dataclass
class Ipv4Header:
    """A validated IPv4 header with the fields pcapkit exposes."""

    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    dont_fragment: bool
    more_fragments: bool
    fragment_offset: int
    time_to_live: int
    protocol: int
    header_checksum: int
    checksum_valid: bool
    source: str
    destination: str
    options_length: int = 0

    @property
    def protocol_name(self) -> str:
        """Return the IP protocol as a readable name."""
        return ip_protocol_name(self.protocol)

    @property
    def fragmented(self) -> bool:
        """Return whether the datagram is part of an IP fragmentation chain."""
        return self.more_fragments or self.fragment_offset > 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "ihl": self.ihl,
            "dscp": self.dscp,
            "ecn": self.ecn,
            "total_length": self.total_length,
            "identification": self.identification,
            "dont_fragment": self.dont_fragment,
            "more_fragments": self.more_fragments,
            "fragment_offset": self.fragment_offset,
            "fragmented": self.fragmented,
            "time_to_live": self.time_to_live,
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "header_checksum": self.header_checksum,
            "checksum_valid": self.checksum_valid,
            "source": self.source,
            "destination": self.destination,
            "options_length": self.options_length,
        }


@dataclass
class Ipv6Header:
    """An IPv6 header after walking the next-header chain."""

    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    source: str
    destination: str
    transport_next_header: int | None = None
    extension_headers: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "traffic_class": self.traffic_class,
            "flow_label": self.flow_label,
            "payload_length": self.payload_length,
            "next_header": self.next_header,
            "next_header_name": ip_protocol_name(self.next_header),
            "transport_next_header": self.transport_next_header,
            "transport_next_header_name": (
                ip_protocol_name(self.transport_next_header)
                if self.transport_next_header is not None
                else None
            ),
            "hop_limit": self.hop_limit,
            "source": self.source,
            "destination": self.destination,
            "extension_headers": list(self.extension_headers),
        }


@dataclass
class TcpSegment:
    """A decoded TCP segment."""

    source_port: int
    destination_port: int
    sequence: int
    acknowledgement: int
    header_length: int
    flags: list[str]
    window: int
    checksum: int
    urgent_pointer: int
    payload_length: int

    @property
    def flags_text(self) -> str:
        """Return the TCP flags as a comma-separated string."""
        return ",".join(self.flags) if self.flags else "none"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "sequence": self.sequence,
            "acknowledgement": self.acknowledgement,
            "header_length": self.header_length,
            "flags": list(self.flags),
            "window": self.window,
            "checksum": self.checksum,
            "urgent_pointer": self.urgent_pointer,
            "payload_length": self.payload_length,
        }


@dataclass
class UdpDatagram:
    """A decoded UDP datagram."""

    source_port: int
    destination_port: int
    length: int
    checksum: int
    payload_length: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "length": self.length,
            "checksum": self.checksum,
            "payload_length": self.payload_length,
        }


@dataclass
class IcmpMessage:
    """A decoded ICMP message, including echo request/reply fields."""

    type: int
    code: int
    checksum: int
    type_name: str
    echo_id: int | None
    echo_sequence: int | None
    payload_length: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "type": self.type,
            "code": self.code,
            "checksum": self.checksum,
            "type_name": self.type_name,
            "echo_id": self.echo_id,
            "echo_sequence": self.echo_sequence,
            "payload_length": self.payload_length,
        }


@dataclass
class Icmpv6Message:
    """A decoded ICMPv6 message."""

    type: int
    code: int
    checksum: int
    type_name: str
    echo_id: int | None
    echo_sequence: int | None
    payload_length: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "type": self.type,
            "code": self.code,
            "checksum": self.checksum,
            "type_name": self.type_name,
            "echo_id": self.echo_id,
            "echo_sequence": self.echo_sequence,
            "payload_length": self.payload_length,
        }


@dataclass
class DnsQuestion:
    """One DNS question."""

    name: str
    qtype: int
    qclass: int

    @property
    def qtype_name(self) -> str:
        """Return the query type as a readable name."""
        return dns_type_name(self.qtype)

    @property
    def qclass_name(self) -> str:
        """Return the query class as a readable name."""
        return dns_class_name(self.qclass)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "name": self.name,
            "qtype": self.qtype,
            "qtype_name": self.qtype_name,
            "qclass": self.qclass,
            "qclass_name": self.qclass_name,
        }


@dataclass
class DnsRecord:
    """One decoded DNS resource record.

    ``value`` is a presentation-format string for the record types pcapkit
    understands and an honest placeholder for the others.
    """

    name: str
    rtype: int
    ttl: int
    value: str

    @property
    def rtype_name(self) -> str:
        """Return the record type as a readable name."""
        return dns_type_name(self.rtype)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "name": self.name,
            "rtype": self.rtype,
            "rtype_name": self.rtype_name,
            "ttl": self.ttl,
            "value": self.value,
        }


@dataclass
class DnsMessage:
    """A compact decoded DNS message (header, question and answer sections)."""

    transaction_id: int
    is_response: bool
    opcode: int
    authoritative: bool
    truncated: bool
    recursion_desired: bool
    recursion_available: bool
    rcode: int
    questions: list[DnsQuestion] = field(default_factory=list)
    answers: list[DnsRecord] = field(default_factory=list)

    @property
    def opcode_name(self) -> str:
        """Return the opcode as a readable name."""
        return dns_opcode_name(self.opcode)

    @property
    def rcode_name(self) -> str:
        """Return the response code as a readable name."""
        return dns_rcode_name(self.rcode)

    @property
    def kind(self) -> str:
        """Return ``query`` or ``response``."""
        return "response" if self.is_response else "query"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "transaction_id": self.transaction_id,
            "kind": self.kind,
            "is_response": self.is_response,
            "opcode": self.opcode,
            "opcode_name": self.opcode_name,
            "authoritative": self.authoritative,
            "truncated": self.truncated,
            "recursion_desired": self.recursion_desired,
            "recursion_available": self.recursion_available,
            "rcode": self.rcode,
            "rcode_name": self.rcode_name,
            "questions": [question.to_dict() for question in self.questions],
            "answers": [answer.to_dict() for answer in self.answers],
        }


@dataclass
class DecodedPacket:
    """A captured packet decoded layer by layer.

    ``notes`` describes decodable-but-incomplete situations (fragments, unknown
    protocols); ``errors`` lists actual decoding problems such as truncation.
    """

    index: int
    timestamp_ns: int
    captured_length: int
    original_length: int
    interface_id: int = 0
    truncated: bool = False
    ethernet: EthernetHeader | None = None
    vlans: list[VlanTag] = field(default_factory=list)
    arp: ArpPacket | None = None
    ipv4: Ipv4Header | None = None
    ipv6: Ipv6Header | None = None
    tcp: TcpSegment | None = None
    udp: UdpDatagram | None = None
    icmp: IcmpMessage | None = None
    icmpv6: Icmpv6Message | None = None
    dns: DnsMessage | None = None
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def network_protocol(self) -> str | None:
        """Return the decoded network-layer protocol name, if any."""
        if self.arp is not None:
            return "ARP"
        if self.ipv4 is not None:
            return "IPv4"
        if self.ipv6 is not None:
            return "IPv6"
        return None

    @property
    def transport_protocol(self) -> str | None:
        """Return the decoded transport-layer protocol name, if any."""
        if self.tcp is not None:
            return "TCP"
        if self.udp is not None:
            return "UDP"
        if self.icmp is not None:
            return "ICMP"
        if self.icmpv6 is not None:
            return "ICMPv6"
        return None

    @property
    def protocol_label(self) -> str:
        """Return the highest decoded protocol, used for distributions."""
        if self.dns is not None:
            return "DNS"
        if self.transport_protocol is not None:
            return self.transport_protocol
        if self.arp is not None:
            return "ARP"
        if self.ipv4 is not None:
            return f"IPv4/{self.ipv4.protocol_name}"
        if self.ipv6 is not None:
            return f"IPv6/{ip_protocol_name(self.ipv6.next_header)}"
        if self.ethernet is not None:
            return f"EtherType {self.ethernet.ethertype_name}"
        return "Unknown"

    @property
    def source_ip(self) -> str | None:
        """Return the source IP address, if the packet has one."""
        if self.ipv4 is not None:
            return self.ipv4.source
        if self.ipv6 is not None:
            return self.ipv6.source
        return None

    @property
    def destination_ip(self) -> str | None:
        """Return the destination IP address, if the packet has one."""
        if self.ipv4 is not None:
            return self.ipv4.destination
        if self.ipv6 is not None:
            return self.ipv6.destination
        return None

    @property
    def source_port(self) -> int | None:
        """Return the transport source port, if the packet has one."""
        if self.tcp is not None:
            return self.tcp.source_port
        if self.udp is not None:
            return self.udp.source_port
        return None

    @property
    def destination_port(self) -> int | None:
        """Return the transport destination port, if the packet has one."""
        if self.tcp is not None:
            return self.tcp.destination_port
        if self.udp is not None:
            return self.udp.destination_port
        return None

    @property
    def has_ip(self) -> bool:
        """Return whether the packet was decoded up to an IP header."""
        return self.ipv4 is not None or self.ipv6 is not None

    def to_dict(self, summary: str | None = None) -> dict[str, Any]:
        """Return a JSON-friendly representation, omitting absent layers."""
        payload: dict[str, Any] = {
            "index": self.index,
            "timestamp_ns": self.timestamp_ns,
            "captured_length": self.captured_length,
            "original_length": self.original_length,
            "interface_id": self.interface_id,
            "truncated": self.truncated,
            "protocol": self.protocol_label,
            "ethernet": self.ethernet.to_dict() if self.ethernet is not None else None,
            "vlans": [tag.to_dict() for tag in self.vlans],
            "notes": list(self.notes),
            "errors": list(self.errors),
        }
        if summary is not None:
            payload["summary"] = summary
        for name in ("arp", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "dns"):
            value = getattr(self, name)
            if value is not None:
                payload[name] = value.to_dict()
        return payload
