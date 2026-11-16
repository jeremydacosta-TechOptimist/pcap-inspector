"""Tests for the pcapng reader (SHB/IDB/EPB)."""

from __future__ import annotations

import struct
import unittest

import support

from pcapkit.errors import PcapError
from pcapkit.pcapng import parse_pcapng


class PcapngReaderTests(unittest.TestCase):
    """Reading handcrafted pcapng files."""

    def _two_packet_file(self) -> bytes:
        return (
            support.pcapng_shb()
            + support.pcapng_idb(linktype=1, snaplen=65535)
            + support.pcapng_epb(0, 1_700_000_000_000_000, b"\x01" * 20)
            + support.pcapng_epb(0, 1_700_000_001_250_000, b"\x02" * 14)
        )

    def test_reads_section_header_and_packets(self) -> None:
        capture = parse_pcapng(self._two_packet_file(), source="fixture.pcapng")
        self.assertEqual(capture.format, "pcapng")
        self.assertEqual(capture.version, "1.0")
        self.assertEqual(capture.byte_order, "little")
        self.assertEqual(capture.linktype, 1)
        self.assertEqual(capture.snaplen, 65535)
        self.assertEqual(len(capture.interfaces), 1)
        self.assertEqual(len(capture.packets), 2)
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_000_000_000)
        self.assertEqual(capture.packets[1].timestamp_ns, 1_700_000_001_250_000_000)
        self.assertEqual(capture.packets[0].data, b"\x01" * 20)
        self.assertEqual(capture.warnings, [])

    def test_big_endian_section(self) -> None:
        data = (
            support.pcapng_shb(endian=">")
            + support.pcapng_idb(endian=">")
            + support.pcapng_epb(0, 1_700_000_000_000_000, b"\xaa" * 16, endian=">")
        )
        capture = parse_pcapng(data, source="big-endian.pcapng")
        self.assertEqual(capture.byte_order, "big")
        self.assertEqual(len(capture.packets), 1)
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_000_000_000)

    def test_interface_options_are_decoded(self) -> None:
        options = {2: b"eth0", 3: b"lab interface", 9: b"\x09"}
        data = (
            support.pcapng_shb()
            + support.pcapng_idb(options=options)
            + support.pcapng_epb(0, 1_700_000_000_123_456_789, b"\x00" * 12)
        )
        capture = parse_pcapng(data, source="options.pcapng")
        interface = capture.interfaces[0]
        self.assertEqual(interface.name, "eth0")
        self.assertEqual(interface.description, "lab interface")
        self.assertEqual(interface.timestamp_resolution, 9)
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_123_456_789)

    def test_interface_timestamp_offset_is_applied(self) -> None:
        options = {14: struct.pack("<q", 10)}
        data = (
            support.pcapng_shb()
            + support.pcapng_idb(options=options)
            + support.pcapng_epb(0, 0, b"\x00" * 12)
        )
        capture = parse_pcapng(data, source="offset.pcapng")
        self.assertEqual(capture.packets[0].timestamp_ns, 10_000_000_000)

    def test_multiple_interfaces_keep_their_index(self) -> None:
        data = (
            support.pcapng_shb()
            + support.pcapng_idb(linktype=1, options={2: b"eth0"})
            + support.pcapng_idb(linktype=1, options={2: b"eth1"})
            + support.pcapng_epb(1, 1_700_000_000_000_000, b"\x00" * 8)
        )
        capture = parse_pcapng(data, source="multi.pcapng")
        self.assertEqual(len(capture.interfaces), 2)
        self.assertEqual(capture.interfaces[1].name, "eth1")
        self.assertEqual(capture.packets[0].interface_id, 1)
        self.assertEqual(capture.packets[0].linktype, 1)

    def test_unknown_interface_is_reported(self) -> None:
        data = (
            support.pcapng_shb()
            + support.pcapng_idb()
            + support.pcapng_epb(7, 1_700_000_000_000_000, b"\x00" * 8)
        )
        capture = parse_pcapng(data, source="bad-interface.pcapng")
        self.assertEqual(len(capture.packets), 1)
        self.assertTrue(
            any("unknown interface 7" in warning for warning in capture.warnings)
        )

    def test_unknown_block_is_skipped(self) -> None:
        data = (
            support.pcapng_shb()
            + support.pcapng_idb()
            + support.pcapng_block(0x00000BAD, b"custom block")
            + support.pcapng_epb(0, 1_700_000_000_000_000, b"\x00" * 8)
        )
        capture = parse_pcapng(data, source="unknown-block.pcapng")
        self.assertEqual(len(capture.packets), 1)
        self.assertTrue(any("skipped block type" in warning for warning in capture.warnings))

    def test_simple_packet_block_is_skipped(self) -> None:
        packet = b"\x00" * 8
        spb = support.pcapng_block(3, struct.pack("<I", len(packet)) + packet)
        data = support.pcapng_shb() + support.pcapng_idb() + spb
        capture = parse_pcapng(data, source="spb.pcapng")
        self.assertEqual(capture.packets, [])
        self.assertTrue(any("Simple Packet Block" in warning for warning in capture.warnings))

    def test_corrupt_block_length_stops_reading(self) -> None:
        good = support.pcapng_epb(0, 1_700_000_000_000_000, b"\x00" * 8)
        corrupt = good[:-4] + struct.pack("<I", 999)
        data = support.pcapng_shb() + support.pcapng_idb() + good + corrupt
        capture = parse_pcapng(data, source="corrupt.pcapng")
        self.assertEqual(len(capture.packets), 1)
        self.assertTrue(
            any("mismatched length fields" in warning for warning in capture.warnings)
        )

    def test_truncated_block_is_reported(self) -> None:
        data = self._two_packet_file()
        capture = parse_pcapng(data[:-8], source="truncated.pcapng")
        self.assertEqual(len(capture.packets), 1)
        self.assertTrue(any("truncated block" in warning for warning in capture.warnings))

    def test_missing_section_header_raises(self) -> None:
        with self.assertRaises(PcapError):
            parse_pcapng(support.pcapng_idb(), source="no-shb.pcapng")

    def test_invalid_byte_order_magic_raises(self) -> None:
        block = support.pcapng_block(0x0A0D0D0A, b"\x00" * 16)
        with self.assertRaises(PcapError):
            parse_pcapng(block, source="bad-bom.pcapng")

    def test_section_without_packets_is_valid(self) -> None:
        capture = parse_pcapng(
            support.pcapng_shb() + support.pcapng_idb(), source="empty.pcapng"
        )
        self.assertEqual(capture.packets, [])
        self.assertEqual(len(capture.interfaces), 1)


if __name__ == "__main__":
    unittest.main()
