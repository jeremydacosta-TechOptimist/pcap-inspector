"""Capture analysis: flow aggregation, talkers, protocol distribution, summary.

A flow is a bidirectional 5-tuple conversation.  The 5-tuple is canonicalised so
both directions aggregate into one flow; the first packet seen defines the
initiator and therefore the forward/reverse direction counts.  Protocols
without ports (ICMP, ICMPv6, other IP protocols) aggregate on the address pair.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from .decode import decode_capture, describe_packet
from .models import Capture, DecodedPacket, InterfaceInfo
from .util import endpoint_to_string


@dataclass
class Flow:
    """A bidirectional conversation between two endpoints."""

    protocol: str
    initiator: str
    responder: str
    packets: int = 0
    bytes: int = 0
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    first_timestamp_ns: int = 0
    last_timestamp_ns: int = 0

    @property
    def duration_ns(self) -> int:
        """Return the conversation duration in nanoseconds."""
        return max(0, self.last_timestamp_ns - self.first_timestamp_ns)

    @property
    def label(self) -> str:
        """Return a readable one-line label for the conversation."""
        return f"{self.protocol} {self.initiator} <-> {self.responder}"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "protocol": self.protocol,
            "initiator": self.initiator,
            "responder": self.responder,
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_forward": self.packets_forward,
            "packets_reverse": self.packets_reverse,
            "bytes_forward": self.bytes_forward,
            "bytes_reverse": self.bytes_reverse,
            "first_timestamp_ns": self.first_timestamp_ns,
            "last_timestamp_ns": self.last_timestamp_ns,
            "duration_ns": self.duration_ns,
        }


@dataclass
class Talker:
    """Aggregated traffic for one IP address."""

    address: str
    packets: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def bytes_total(self) -> int:
        """Return the total number of frame bytes involving this address."""
        return self.bytes_sent + self.bytes_received

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "address": self.address,
            "packets": self.packets,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "bytes_total": self.bytes_total,
        }


@dataclass
class CaptureSummary:
    """Aggregate statistics for one capture."""

    packets: int
    captured_bytes: int
    wire_bytes: int
    first_timestamp_ns: int | None
    last_timestamp_ns: int | None
    duration_ns: int
    packets_per_second: float
    bits_per_second: float
    truncated_packets: int
    packets_with_errors: int
    notes_count: int
    dns_messages: int
    flow_count: int
    talker_count: int
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    protocols: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "packets": self.packets,
            "captured_bytes": self.captured_bytes,
            "wire_bytes": self.wire_bytes,
            "first_timestamp_ns": self.first_timestamp_ns,
            "last_timestamp_ns": self.last_timestamp_ns,
            "duration_ns": self.duration_ns,
            "packets_per_second": self.packets_per_second,
            "bits_per_second": self.bits_per_second,
            "truncated_packets": self.truncated_packets,
            "packets_with_errors": self.packets_with_errors,
            "notes_count": self.notes_count,
            "dns_messages": self.dns_messages,
            "flow_count": self.flow_count,
            "talker_count": self.talker_count,
            "interfaces": [interface.to_dict() for interface in self.interfaces],
            "warnings": list(self.warnings),
            "protocols": dict(self.protocols),
        }


class CaptureAnalysis:
    """Everything derived from one decoded capture."""

    def __init__(self, capture: Capture) -> None:
        self.capture = capture
        self.decoded: list[DecodedPacket] = decode_capture(capture)
        self.flows: list[Flow] = build_flows(self.decoded)
        self.talkers: list[Talker] = build_talkers(self.decoded)
        self.protocol_counts: Counter[str] = Counter(
            packet.protocol_label for packet in self.decoded
        )
        self.dns_packets: list[DecodedPacket] = [
            packet for packet in self.decoded if packet.dns is not None
        ]
        self.summary = build_summary(capture, self.decoded, self.flows, self.talkers)

    def top_flows(self, limit: int = 10) -> list[Flow]:
        """Return the busiest conversations, largest first."""
        return self.flows[: max(0, limit)] if limit else list(self.flows)

    def top_talkers(self, limit: int = 10) -> list[Talker]:
        """Return the talkers with most traffic, largest first."""
        return self.talkers[: max(0, limit)] if limit else list(self.talkers)

    def protocol_distribution(self) -> list[tuple[str, int]]:
        """Return protocol labels and packet counts, most frequent first."""
        return sorted(
            self.protocol_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )

    def packet_summaries(self, limit: int = 0) -> list[dict[str, object]]:
        """Return JSON-friendly packet entries, optionally limited."""
        packets = self.decoded if not limit else self.decoded[:limit]
        return [
            packet.to_dict(summary=describe_packet(packet)) for packet in packets
        ]


def analyze(capture: Capture) -> CaptureAnalysis:
    """Decode and analyse a capture."""
    return CaptureAnalysis(capture)


def build_flows(packets: Iterable[DecodedPacket]) -> list[Flow]:
    """Aggregate decoded IP packets into bidirectional conversations."""
    flows: dict[tuple[str, tuple[str, str]], Flow] = {}
    for packet in packets:
        if not packet.has_ip:
            continue
        protocol = packet.transport_protocol or packet.protocol_label
        source = endpoint_to_string(packet.source_ip or "?", packet.source_port)
        destination = endpoint_to_string(packet.destination_ip or "?", packet.destination_port)
        key = (protocol, tuple(sorted((source, destination))))
        flow = flows.get(key)
        if flow is None:
            flow = Flow(
                protocol=protocol,
                initiator=source,
                responder=destination,
                first_timestamp_ns=packet.timestamp_ns,
                last_timestamp_ns=packet.timestamp_ns,
            )
            flows[key] = flow
        length = packet.captured_length
        flow.packets += 1
        flow.bytes += length
        if source == flow.initiator:
            flow.packets_forward += 1
            flow.bytes_forward += length
        else:
            flow.packets_reverse += 1
            flow.bytes_reverse += length
        flow.first_timestamp_ns = min(flow.first_timestamp_ns, packet.timestamp_ns)
        flow.last_timestamp_ns = max(flow.last_timestamp_ns, packet.timestamp_ns)
    return sorted(flows.values(), key=lambda flow: (-flow.bytes, -flow.packets, flow.label))


def build_talkers(packets: Iterable[DecodedPacket]) -> list[Talker]:
    """Aggregate sent and received bytes per IP address."""
    talkers: dict[str, Talker] = {}
    for packet in packets:
        if not packet.has_ip:
            continue
        source = packet.source_ip
        destination = packet.destination_ip
        assert source is not None and destination is not None  # guaranteed by has_ip
        length = packet.captured_length
        sender = talkers.get(source)
        if sender is None:
            sender = talkers[source] = Talker(address=source)
        sender.packets += 1
        sender.bytes_sent += length
        if destination != source:
            receiver = talkers.get(destination)
            if receiver is None:
                receiver = talkers[destination] = Talker(address=destination)
            receiver.packets += 1
            receiver.bytes_received += length
    return sorted(talkers.values(), key=lambda talker: (-talker.bytes_total, talker.address))


def build_summary(
    capture: Capture,
    packets: list[DecodedPacket],
    flows: list[Flow],
    talkers: list[Talker],
) -> CaptureSummary:
    """Compute the capture summary from decoded packets and derived data."""
    captured_bytes = sum(packet.captured_length for packet in packets)
    wire_bytes = sum(packet.original_length for packet in packets)
    timestamps = [packet.timestamp_ns for packet in packets]
    first_timestamp_ns = min(timestamps) if timestamps else None
    last_timestamp_ns = max(timestamps) if timestamps else None
    duration_ns = (
        (last_timestamp_ns - first_timestamp_ns)
        if first_timestamp_ns is not None and last_timestamp_ns is not None
        else 0
    )
    duration_seconds = duration_ns / 1_000_000_000
    packets_per_second = len(packets) / duration_seconds if duration_seconds > 0 else 0.0
    bits_per_second = wire_bytes * 8 / duration_seconds if duration_seconds > 0 else 0.0
    protocols = Counter(packet.protocol_label for packet in packets)
    return CaptureSummary(
        packets=len(packets),
        captured_bytes=captured_bytes,
        wire_bytes=wire_bytes,
        first_timestamp_ns=first_timestamp_ns,
        last_timestamp_ns=last_timestamp_ns,
        duration_ns=duration_ns,
        packets_per_second=packets_per_second,
        bits_per_second=bits_per_second,
        truncated_packets=sum(1 for packet in packets if packet.truncated),
        packets_with_errors=sum(1 for packet in packets if packet.errors),
        notes_count=sum(len(packet.notes) for packet in packets),
        dns_messages=sum(1 for packet in packets if packet.dns is not None),
        flow_count=len(flows),
        talker_count=len(talkers),
        interfaces=list(capture.interfaces),
        warnings=list(capture.warnings),
        protocols=dict(sorted(protocols.items(), key=lambda item: (-item[1], item[0]))),
    )
