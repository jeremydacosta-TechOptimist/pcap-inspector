"""Tests for the classic pcap reader and writer."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

import support

from pcapkit.errors import PcapError
from pcapkit.models import CapturedPacket
from pcapkit.pcap import parse_pcap, read_pcap, write_pcap


class PcapReaderTests(unittest.TestCase):
    """Reading handcrafted classic pcap files."""

    def test_reads_little_endian_microsecond_capture(self) -> None:
        first = b"\xaa" * 20
        second = b"\xbb" * 14
        data = support.pcap_bytes(
            [
                support.pcap_record(1_700_000_000, 123_456, first),
                support.pcap_record(1_700_000_001, 5, second, original_length=60),
            ]
        )
        capture = parse_pcap(data, source="fixture.pcap")
        self.assertEqual(capture.format, "pcap")
        self.assertEqual(capture.byte_order, "little")
        self.assertEqual(capture.version, "2.4")
        self.assertEqual(capture.linktype, 1)
        self.assertEqual(capture.snaplen, 65535)
        self.assertEqual(len(capture.packets), 2)
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_123_456_000)
        self.assertEqual(capture.packets[0].data, first)
        self.assertEqual(capture.packets[1].timestamp_ns, 1_700_000_001_000_005_000)
        self.assertEqual(capture.packets[1].original_length, 60)
        self.assertEqual(capture.packets[1].captured_length, 14)
        self.assertFalse(capture.packets[0].truncated)
        self.assertEqual(capture.warnings, [])
        self.assertEqual(len(capture.interfaces), 1)
        self.assertEqual(capture.interfaces[0].linktype, 1)

    def test_reads_big_endian_nanosecond_capture(self) -> None:
        payload = b"\x01\x02\x03\x04" * 4
        data = support.pcap_bytes(
            [
                support.pcap_record(1_700_000_000, 123_456_789, payload),
                support.pcap_record(1_700_000_002, 1, payload),
            ],
            endian=">",
            nanosecond=True,
        )
        capture = parse_pcap(data, source="fixture-big-endian.pcap")
        self.assertEqual(capture.byte_order, "big")
        self.assertEqual(len(capture.packets), 2)
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_123_456_789)
        self.assertEqual(capture.packets[1].timestamp_ns, 1_700_000_002_000_000_001)
        self.assertEqual(capture.interfaces[0].timestamp_resolution, 9)

    def test_unknown_magic_number_raises(self) -> None:
        data = b"\x00\x01\x02\x03" + b"\x00" * 40
        with self.assertRaises(PcapError):
            parse_pcap(data)

    def test_too_short_file_raises(self) -> None:
        with self.assertRaises(PcapError):
            parse_pcap(b"\xd4\xc3\xb2\xa1\x02\x00")

    def test_empty_capture_reads_with_no_packets(self) -> None:
        capture = parse_pcap(support.pcap_bytes([]), source="empty.pcap")
        self.assertEqual(capture.packets, [])
        self.assertEqual(capture.warnings, [])

    def test_truncated_record_data_is_kept_with_warning(self) -> None:
        payload = b"\xcc" * 30
        data = support.pcap_bytes([support.pcap_record(1_700_000_000, 0, payload)])
        capture = parse_pcap(data[:-10], source="truncated.pcap")
        self.assertEqual(len(capture.packets), 1)
        self.assertEqual(len(capture.packets[0].data), 20)
        self.assertTrue(capture.packets[0].truncated)
        self.assertEqual(capture.packets[0].original_length, 30)
        self.assertTrue(any("truncated record 1" in warning for warning in capture.warnings))

    def test_truncated_record_header_is_reported(self) -> None:
        data = support.pcap_bytes([support.pcap_record(1_700_000_000, 0, b"\x01" * 10)])
        capture = parse_pcap(data + b"\x00" * 8, source="truncated.pcap")
        self.assertEqual(len(capture.packets), 1)
        self.assertTrue(
            any("truncated record header" in warning for warning in capture.warnings)
        )

    def test_corrupt_capture_length_stops_reading(self) -> None:
        header = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        corrupt_record = struct.pack("<IIII", 1_700_000_000, 0, 0x10000000, 0x10000000)
        capture = parse_pcap(header + corrupt_record, source="corrupt.pcap")
        self.assertEqual(capture.packets, [])
        self.assertTrue(any("corrupt captured length" in warning for warning in capture.warnings))

    def test_zero_length_record_is_kept_with_warning(self) -> None:
        data = support.pcap_bytes([support.pcap_record(1_700_000_000, 0, b"")])
        capture = parse_pcap(data, source="zero.pcap")
        self.assertEqual(len(capture.packets), 1)
        self.assertEqual(capture.packets[0].data, b"")
        self.assertTrue(any("no packet data" in warning for warning in capture.warnings))

    def test_original_length_smaller_than_capture_is_reported(self) -> None:
        data = support.pcap_bytes(
            [support.pcap_record(1_700_000_000, 0, b"\x00" * 10, original_length=4)]
        )
        capture = parse_pcap(data, source="odd.pcap")
        self.assertTrue(any("original length" in warning for warning in capture.warnings))

    def test_unsupported_link_type_is_reported(self) -> None:
        data = support.pcap_bytes(
            [support.pcap_record(1_700_000_000, 0, b"\x00" * 10)],
            linktype=101,
        )
        capture = parse_pcap(data, source="raw.pcap")
        self.assertEqual(capture.linktype, 101)
        self.assertTrue(any("not Ethernet" in warning for warning in capture.warnings))


class PcapWriterTests(unittest.TestCase):
    """Writer output and writer-to-reader round trips."""

    def _packets(self) -> list[CapturedPacket]:
        return [
            CapturedPacket(timestamp_ns=1_700_000_000_123_456_000, data=b"\x01" * 12, original_length=12),
            CapturedPacket(timestamp_ns=1_700_000_000_999_999_000, data=b"\x02" * 7, original_length=40),
        ]

    def test_round_trip_microsecond(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            written = write_pcap(path, self._packets())
            self.assertEqual(written, 2)
            capture = read_pcap(path)
        self.assertEqual(capture.source, "capture.pcap")
        self.assertEqual(len(capture.packets), 2)
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_123_456_000)
        self.assertEqual(capture.packets[1].original_length, 40)
        self.assertEqual(capture.packets[1].data, b"\x02" * 7)

    def test_round_trip_nanosecond(self) -> None:
        packets = [
            CapturedPacket(timestamp_ns=1_700_000_000_123_456_789, data=b"\x03" * 20, original_length=20)
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nanosecond.pcap"
            write_pcap(path, packets, nanosecond=True)
            raw = path.read_bytes()
            capture = read_pcap(path)
        self.assertEqual(raw[:4], b"\x4d\x3c\xb2\xa1")
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_123_456_789)
        self.assertEqual(capture.interfaces[0].timestamp_resolution, 9)

    def test_microsecond_writer_truncates_nanoseconds(self) -> None:
        packets = [
            CapturedPacket(timestamp_ns=1_700_000_000_123_456_789, data=b"\x00", original_length=1)
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "micro.pcap"
            write_pcap(path, packets)
            capture = read_pcap(path)
        self.assertEqual(capture.packets[0].timestamp_ns, 1_700_000_000_123_456_000)

    def test_little_endian_magic_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "le.pcap"
            write_pcap(path, [], byte_order="little", nanosecond=False)
            self.assertEqual(path.read_bytes()[:4], b"\xd4\xc3\xb2\xa1")

    def test_big_endian_nanosecond_magic_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "be.pcap"
            write_pcap(path, [], byte_order="big", nanosecond=True)
            self.assertEqual(path.read_bytes()[:4], b"\xa1\xb2\x3c\x4d")

    def test_invalid_byte_order_raises(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                write_pcap(Path(directory) / "bad.pcap", [], byte_order="middle")

    def test_link_type_and_snaplen_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.pcap"
            write_pcap(path, self._packets(), linktype=1, snaplen=9000)
            capture = read_pcap(path)
        self.assertEqual(capture.snaplen, 9000)
        self.assertEqual(capture.linktype, 1)
        self.assertEqual(capture.warnings, [])


if __name__ == "__main__":
    unittest.main()
