"""Tests for flow aggregation, talkers, protocol distribution and summaries."""

from __future__ import annotations

import unittest

import support

from pcapkit.analysis import analyze, build_flows, build_talkers
from pcapkit.decode import decode_capture
from pcapkit.models import Capture, CapturedPacket

BASE_TS = 1_700_000_000_000_000_000


def udp_frame(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    payload: bytes = b"payload",
    *,
    ip_version: int = 4,
) -> bytes:
    """Build a complete Ethernet/IP/UDP frame."""
    udp = support.udp_datagram(
        payload,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        ip_version=ip_version,
    )
    if ip_version == 4:
        ip = support.ipv4_packet(
            udp, source=source, destination=destination, protocol=17
        )
        return support.ethernet(ip)
    ip = support.ipv6_packet(udp, source=source, destination=destination, next_header=17)
    return support.ethernet(ip, ethertype=support.ETHERTYPE_IPV6)


def tcp_frame(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    flags: list[str],
    payload: bytes = b"",
) -> bytes:
    """Build a complete Ethernet/IPv4/TCP frame."""
    segment = support.tcp_segment(
        flags,
        payload,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
    )
    return support.ethernet(
        support.ipv4_packet(segment, source=source, destination=destination, protocol=6)
    )


def icmp_frame(source: str, destination: str) -> bytes:
    """Build a complete Ethernet/IPv4/ICMP echo request frame."""
    return support.ethernet(
        support.ipv4_packet(support.icmp_echo(), source=source, destination=destination, protocol=1)
    )


def make_capture(frames: list[tuple[int, bytes]]) -> Capture:
    """Build a capture from ``(timestamp_ns, frame_bytes)`` pairs."""
    packets = [
        CapturedPacket(timestamp_ns=timestamp, data=frame, original_length=len(frame))
        for timestamp, frame in frames
    ]
    return Capture(
        source="fixture.pcap",
        format="pcap",
        byte_order="little",
        version="2.4",
        snaplen=65535,
        linktype=1,
        packets=packets,
    )


class FlowTests(unittest.TestCase):
    """Bidirectional 5-tuple aggregation."""

    def test_two_directions_aggregate_into_one_flow(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, udp_frame("192.0.2.10", "198.51.100.53", 49152, 53)),
                (BASE_TS + 50_000_000, udp_frame("198.51.100.53", "192.0.2.10", 53, 49152)),
            ]
        )
        analysis = analyze(capture)
        self.assertEqual(len(analysis.flows), 1)
        flow = analysis.flows[0]
        self.assertEqual(flow.protocol, "UDP")
        self.assertEqual(flow.initiator, "192.0.2.10:49152")
        self.assertEqual(flow.responder, "198.51.100.53:53")
        self.assertEqual(flow.packets, 2)
        self.assertEqual(flow.packets_forward, 1)
        self.assertEqual(flow.packets_reverse, 1)
        self.assertEqual(flow.bytes_forward, len(capture.packets[0].data))
        self.assertEqual(flow.duration_ns, 50_000_000)

    def test_flow_direction_is_relative_to_first_packet(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, udp_frame("198.51.100.53", "192.0.2.10", 53, 49152)),
                (BASE_TS + 10_000_000, udp_frame("192.0.2.10", "198.51.100.53", 49152, 53)),
            ]
        )
        flow = analyze(capture).flows[0]
        self.assertEqual(flow.initiator, "198.51.100.53:53")
        self.assertEqual(flow.packets_forward, 1)
        self.assertEqual(flow.packets_reverse, 1)

    def test_flows_are_sorted_by_bytes(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, tcp_frame("192.0.2.10", "198.51.100.80", 49876, 80, ["SYN"])),
                (BASE_TS + 1_000, tcp_frame("192.0.2.10", "198.51.100.80", 49876, 80, ["ACK"], b"x" * 100)),
                (BASE_TS + 2_000, udp_frame("192.0.2.30", "198.51.100.53", 5353, 53, b"y" * 200)),
            ]
        )
        analysis = analyze(capture)
        self.assertEqual(len(analysis.flows), 2)
        self.assertEqual(analysis.flows[0].protocol, "UDP")
        self.assertGreater(analysis.flows[0].bytes, analysis.flows[1].bytes)
        self.assertEqual(analysis.top_flows(1)[0].protocol, "UDP")
        self.assertEqual(len(analysis.top_flows(0)), 2)

    def test_icmp_flow_uses_address_pair(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, icmp_frame("192.0.2.30", "192.0.2.20")),
                (BASE_TS + 500_000, icmp_frame("192.0.2.20", "192.0.2.30")),
            ]
        )
        flow = analyze(capture).flows[0]
        self.assertEqual(flow.protocol, "ICMP")
        self.assertEqual(flow.initiator, "192.0.2.30")
        self.assertEqual(flow.responder, "192.0.2.20")
        self.assertNotIn(":", flow.initiator)

    def test_ipv6_flow_endpoints_are_bracketed(self) -> None:
        capture = make_capture(
            [
                (
                    BASE_TS,
                    udp_frame("2001:db8::10", "2001:db8::53", 5353, 53, ip_version=6),
                )
            ]
        )
        flow = analyze(capture).flows[0]
        self.assertEqual(flow.initiator, "[2001:db8::10]:5353")
        self.assertEqual(flow.responder, "[2001:db8::53]:53")

    def test_dns_packets_keep_the_udp_flow_protocol(self) -> None:
        dns_payload = support.dns_query("www.example.com", 1)
        capture = make_capture(
            [
                (BASE_TS, udp_frame("192.0.2.10", "198.51.100.53", 49152, 53, dns_payload)),
                (
                    BASE_TS + 20_000_000,
                    udp_frame(
                        "198.51.100.53",
                        "192.0.2.10",
                        53,
                        49152,
                        support.dns_response(
                            "www.example.com",
                            1,
                            [(support.QUESTION_POINTER, 1, 300, support.ip4("203.0.113.10"))],
                        ),
                    ),
                ),
            ]
        )
        analysis = analyze(capture)
        self.assertEqual(len(analysis.flows), 1)
        self.assertEqual(analysis.flows[0].protocol, "UDP")
        self.assertEqual(analysis.summary.dns_messages, 2)
        self.assertIn(("DNS", 2), analysis.protocol_distribution())

    def test_build_flows_and_talkers_accept_decoded_packets(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, udp_frame("192.0.2.10", "198.51.100.53", 49152, 53)),
            ]
        )
        decoded = decode_capture(capture)
        self.assertEqual(len(build_flows(decoded)), 1)
        self.assertEqual(len(build_talkers(decoded)), 2)


class TalkerTests(unittest.TestCase):
    """Per-address aggregation."""

    def test_talkers_aggregate_sent_and_received(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, udp_frame("192.0.2.10", "198.51.100.53", 49152, 53)),
                (BASE_TS + 1_000, udp_frame("192.0.2.10", "198.51.100.53", 49153, 53)),
                (BASE_TS + 2_000, udp_frame("198.51.100.53", "192.0.2.10", 53, 49152)),
            ]
        )
        talkers = analyze(capture).talkers
        self.assertEqual(len(talkers), 2)
        client, server = talkers[0], talkers[1]
        self.assertEqual(client.address, "192.0.2.10")
        self.assertEqual(client.packets, 3)
        self.assertEqual(client.bytes_sent, 2 * len(capture.packets[0].data))
        self.assertEqual(client.bytes_received, len(capture.packets[2].data))
        self.assertEqual(client.bytes_total, client.bytes_sent + client.bytes_received)
        self.assertEqual(server.address, "198.51.100.53")
        self.assertEqual(server.packets, 3)

    def test_top_talkers_limit(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, udp_frame("192.0.2.10", "198.51.100.53", 49152, 53, b"a" * 100)),
                (BASE_TS + 1_000, udp_frame("192.0.2.30", "203.0.113.50", 50000, 443, b"b" * 10)),
            ]
        )
        analysis = analyze(capture)
        self.assertEqual(len(analysis.top_talkers(1)), 1)
        self.assertEqual(analysis.top_talkers(1)[0].address, "192.0.2.10")
        self.assertEqual(len(analysis.top_talkers(0)), 4)


class SummaryTests(unittest.TestCase):
    """Capture summary arithmetic."""

    def test_rates_are_computed_from_the_time_span(self) -> None:
        first = udp_frame("192.0.2.10", "198.51.100.53", 49152, 9999, b"a" * 92)
        second = udp_frame("192.0.2.53", "198.51.100.53", 49153, 9999, b"b" * 292)
        capture = make_capture([(BASE_TS, first), (BASE_TS + 1_000_000_000, second)])
        summary = analyze(capture).summary
        self.assertEqual(summary.packets, 2)
        self.assertEqual(summary.duration_ns, 1_000_000_000)
        self.assertAlmostEqual(summary.packets_per_second, 2.0)
        expected_bits = (len(first) + len(second)) * 8
        self.assertAlmostEqual(summary.bits_per_second, expected_bits)
        self.assertEqual(summary.captured_bytes, len(first) + len(second))
        self.assertEqual(summary.wire_bytes, len(first) + len(second))
        self.assertEqual(summary.truncated_packets, 0)
        self.assertEqual(summary.packets_with_errors, 0)

    def test_single_packet_has_zero_rate(self) -> None:
        capture = make_capture(
            [(BASE_TS, udp_frame("192.0.2.10", "198.51.100.53", 49152, 53))]
        )
        summary = analyze(capture).summary
        self.assertEqual(summary.duration_ns, 0)
        self.assertEqual(summary.packets_per_second, 0.0)
        self.assertEqual(summary.bits_per_second, 0.0)

    def test_empty_capture_summary_is_zero(self) -> None:
        analysis = analyze(make_capture([]))
        summary = analysis.summary
        self.assertEqual(summary.packets, 0)
        self.assertEqual(summary.captured_bytes, 0)
        self.assertIsNone(summary.first_timestamp_ns)
        self.assertEqual(summary.flow_count, 0)
        self.assertEqual(analysis.flows, [])
        self.assertEqual(analysis.talkers, [])
        self.assertEqual(analysis.protocol_distribution(), [])

    def test_truncated_and_error_counts(self) -> None:
        capture = make_capture(
            [
                (BASE_TS, support.ethernet(b"\x01\x02\x03")),
                (BASE_TS + 1_000, udp_frame("192.0.2.10", "198.51.100.53", 49152, 9999)),
            ]
        )
        capture.packets[0] = CapturedPacket(
            timestamp_ns=BASE_TS,
            data=capture.packets[0].data,
            original_length=60,
            truncated=True,
        )
        summary = analyze(capture).summary
        self.assertEqual(summary.truncated_packets, 1)
        self.assertEqual(summary.packets_with_errors, 1)
        self.assertEqual(summary.wire_bytes, 60 + len(capture.packets[1].data))


if __name__ == "__main__":
    unittest.main()
