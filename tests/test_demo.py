"""Tests for the deterministic synthetic demo capture."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pcapkit.analysis import analyze
from pcapkit.decode import decode_capture
from pcapkit.demo import build_demo_capture, write_demo_capture
from pcapkit.pcap import read_pcap


class DemoCaptureTests(unittest.TestCase):
    """The demo capture content and reproducibility."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.capture = build_demo_capture()
        cls.decoded = decode_capture(cls.capture)
        cls.analysis = analyze(cls.capture)

    def test_packet_count(self) -> None:
        self.assertEqual(len(self.capture.packets), 27)
        self.assertEqual(self.capture.linktype, 1)
        self.assertEqual(self.capture.format, "pcap")

    def test_build_is_deterministic(self) -> None:
        again = build_demo_capture()
        self.assertEqual(
            [(packet.timestamp_ns, packet.data) for packet in self.capture.packets],
            [(packet.timestamp_ns, packet.data) for packet in again.packets],
        )

    def test_protocol_coverage(self) -> None:
        labels = {packet.protocol_label for packet in self.decoded}
        transports = {packet.transport_protocol for packet in self.decoded}
        self.assertIn("ARP", labels)
        self.assertIn("TCP", labels)
        self.assertIn("DNS", labels)
        self.assertIn("ICMP", labels)
        self.assertIn("ICMPv6", labels)
        self.assertTrue({"TCP", "UDP", "ICMP", "ICMPv6"} <= transports)

    def test_vlan_and_qinq_frames_are_present(self) -> None:
        tag_sets = [[tag.vid for tag in packet.vlans] for packet in self.decoded]
        self.assertIn([100], tag_sets)
        self.assertIn([100, 200], tag_sets)

    def test_dns_messages_cover_several_record_types(self) -> None:
        messages = [packet.dns for packet in self.decoded if packet.dns is not None]
        self.assertEqual(len(messages), 8)
        self.assertTrue(any(message.is_response for message in messages))
        self.assertTrue(any(not message.is_response for message in messages))
        record_types = {
            answer.rtype_name
            for message in messages
            for answer in message.answers
        }
        self.assertTrue({"A", "CNAME", "MX", "AAAA"} <= record_types)
        names = {
            question.name
            for message in messages
            for question in message.questions
        }
        self.assertTrue({"www.example.com", "api.example.net", "mail.example.org"} <= names)

    def test_all_packets_decode_without_errors(self) -> None:
        self.assertTrue(all(not packet.errors for packet in self.decoded))
        self.assertTrue(all(not packet.notes for packet in self.decoded))
        for packet in self.decoded:
            if packet.ipv4 is not None:
                self.assertTrue(packet.ipv4.checksum_valid)

    def test_analysis_of_the_demo_capture(self) -> None:
        summary = self.analysis.summary
        self.assertEqual(summary.packets, 27)
        self.assertEqual(summary.flow_count, 8)
        self.assertEqual(summary.talker_count, 9)
        self.assertEqual(summary.dns_messages, 8)
        self.assertEqual(summary.duration_ns, 751_300_000)
        self.assertEqual(summary.truncated_packets, 0)
        self.assertEqual(summary.packets_with_errors, 0)


class DemoFileTests(unittest.TestCase):
    """Writing the demo capture to disk."""

    def test_write_and_read_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.pcap"
            capture = write_demo_capture(str(path))
            self.assertTrue(path.exists())
            self.assertLess(path.stat().st_size, 50 * 1024)
            loaded = read_pcap(path)
        self.assertEqual(len(loaded.packets), 27)
        self.assertEqual(loaded.format, "pcap")
        self.assertEqual(loaded.source, "demo.pcap")
        self.assertEqual(len(capture.packets), 27)
        self.assertEqual(loaded.warnings, [])
        self.assertEqual(
            loaded.packets[0].timestamp_ns, capture.packets[0].timestamp_ns
        )
        self.assertEqual(loaded.packets[-1].data, capture.packets[-1].data)


if __name__ == "__main__":
    unittest.main()
