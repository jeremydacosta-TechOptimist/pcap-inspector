"""Tests for the compact DNS decoder."""

from __future__ import annotations

import socket
import struct
import unittest

import support

from pcapkit.dns import decode_message, decode_name
from pcapkit.errors import DnsDecodeError


class DnsNameTests(unittest.TestCase):
    """Name decoding, including compression pointers."""

    def test_simple_name(self) -> None:
        name, offset = decode_name(support.dns_name("www.example.com"), 0)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, len(support.dns_name("www.example.com")))

    def test_root_name(self) -> None:
        name, offset = decode_name(b"\x00", 0)
        self.assertEqual(name, ".")
        self.assertEqual(offset, 1)

    def test_compression_pointer(self) -> None:
        message = support.dns_name("www.example.com") + b"\x00" * 0
        pointer = b"\xc0\x00"
        name, offset = decode_name(message + pointer, len(message))
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, len(message) + 2)

    def test_pointer_loop_is_detected(self) -> None:
        message = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
        with self.assertRaises(DnsDecodeError):
            decode_message(message)

    def test_pointer_outside_message_is_rejected(self) -> None:
        with self.assertRaises(DnsDecodeError):
            decode_name(b"\xc0\xff", 0)

    def test_invalid_label_length_is_rejected(self) -> None:
        with self.assertRaises(DnsDecodeError):
            decode_name(b"\x40abc", 0)

    def test_name_longer_than_255_bytes_is_rejected(self) -> None:
        labels = b"".join(b"\x3f" + b"a" * 63 for _ in range(4)) + b"\x00"
        with self.assertRaises(DnsDecodeError):
            decode_name(labels, 0)


class DnsMessageTests(unittest.TestCase):
    """Query and response decoding."""

    def test_query(self) -> None:
        message = decode_message(
            support.dns_query("www.example.com", 1, transaction_id=0x1A2B)
        )
        self.assertFalse(message.is_response)
        self.assertEqual(message.transaction_id, 0x1A2B)
        self.assertEqual(message.kind, "query")
        self.assertEqual(message.opcode_name, "QUERY")
        self.assertTrue(message.recursion_desired)
        self.assertEqual(len(message.questions), 1)
        self.assertEqual(message.questions[0].name, "www.example.com")
        self.assertEqual(message.questions[0].qtype_name, "A")
        self.assertEqual(message.questions[0].qclass_name, "IN")
        self.assertEqual(message.answers, [])

    def test_response_with_compressed_answer_name(self) -> None:
        message = decode_message(
            support.dns_response(
                "www.example.com",
                1,
                [
                    (
                        support.QUESTION_POINTER,
                        1,
                        300,
                        socket.inet_pton(socket.AF_INET, "203.0.113.10"),
                    )
                ],
            )
        )
        self.assertTrue(message.is_response)
        self.assertEqual(message.rcode_name, "NOERROR")
        self.assertTrue(message.recursion_available)
        self.assertEqual(len(message.answers), 1)
        self.assertEqual(message.answers[0].name, "www.example.com")
        self.assertEqual(message.answers[0].rtype_name, "A")
        self.assertEqual(message.answers[0].value, "203.0.113.10")
        self.assertEqual(message.answers[0].ttl, 300)

    def test_all_supported_record_types(self) -> None:
        text = b"v=spf1 -all"
        answers = [
            (support.QUESTION_POINTER, 5, 60, support.dns_name("alias.example.com")),
            (support.dns_name("alias.example.com"), 28, 60, socket.inet_pton(socket.AF_INET6, "2001:db8::1")),
            (support.QUESTION_POINTER, 2, 60, support.dns_name("ns1.example.com")),
            (support.dns_name("4.3.2.1.in-addr.arpa"), 12, 60, support.dns_name("host.example.com")),
            (support.QUESTION_POINTER, 15, 60, struct.pack("!H", 10) + support.dns_name("mail.example.com")),
            (support.QUESTION_POINTER, 16, 60, bytes([len(text)]) + text),
        ]
        message = decode_message(support.dns_response("example.com", 1, answers))
        self.assertEqual(len(message.answers), 6)
        self.assertEqual(message.answers[0].name, "example.com")
        self.assertEqual(message.answers[0].value, "alias.example.com")
        self.assertEqual(message.answers[1].name, "alias.example.com")
        self.assertEqual(message.answers[1].value, "2001:db8::1")
        self.assertEqual(message.answers[2].value, "ns1.example.com")
        self.assertEqual(message.answers[3].name, "4.3.2.1.in-addr.arpa")
        self.assertEqual(message.answers[3].value, "host.example.com")
        self.assertEqual(message.answers[4].value, "10 mail.example.com")
        self.assertEqual(message.answers[5].value, "v=spf1 -all")

    def test_multiple_txt_strings(self) -> None:
        rdata = b"\x03abc\x03def"
        message = decode_message(
            support.dns_response(
                "example.com",
                16,
                [(support.QUESTION_POINTER, 16, 60, rdata)],
            )
        )
        self.assertEqual(message.answers[0].value, "abc def")

    def test_nxdomain_rcode(self) -> None:
        message = decode_message(
            support.dns_response("missing.example", 1, [], rcode=3)
        )
        self.assertTrue(message.is_response)
        self.assertEqual(message.rcode, 3)
        self.assertEqual(message.rcode_name, "NXDOMAIN")
        self.assertEqual(message.answers, [])

    def test_unknown_record_type_keeps_hex_value(self) -> None:
        message = decode_message(
            support.dns_response(
                "example.com",
                99,
                [(support.QUESTION_POINTER, 99, 60, b"\xde\xad\xbe\xef")],
            )
        )
        self.assertEqual(message.answers[0].rtype_name, "TYPE99")
        self.assertEqual(message.answers[0].value, "0xdeadbeef")

    def test_authoritative_and_truncated_flags(self) -> None:
        message = decode_message(support.dns_response("example.com", 1, [], rcode=2))
        self.assertFalse(message.authoritative)
        self.assertFalse(message.truncated)
        self.assertEqual(message.rcode_name, "SERVFAIL")


class DnsMalformedTests(unittest.TestCase):
    """Malformed messages must raise DnsDecodeError, never hang or crash."""

    def test_short_header(self) -> None:
        with self.assertRaises(DnsDecodeError):
            decode_message(b"\x00" * 5)

    def test_truncated_question(self) -> None:
        header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        with self.assertRaises(DnsDecodeError):
            decode_message(header + b"\x03www")

    def test_truncated_answer_header(self) -> None:
        message = (
            struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
            + support.dns_name("example.com")
            + struct.pack("!HH", 1, 1)
            + b"\x00\x00\x01"
        )
        with self.assertRaises(DnsDecodeError):
            decode_message(message)

    def test_answer_data_beyond_message(self) -> None:
        message = (
            struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
            + support.dns_name("example.com")
            + struct.pack("!HH", 1, 1)
            + support.dns_name("example.com")
            + struct.pack("!HHIH", 1, 1, 60, 100)
            + b"\x00" * 4
        )
        with self.assertRaises(DnsDecodeError):
            decode_message(message)

    def test_too_many_answers_is_rejected(self) -> None:
        header = struct.pack("!HHHHHH", 1, 0x8180, 0, 100, 0, 0)
        with self.assertRaises(DnsDecodeError):
            decode_message(header)


if __name__ == "__main__":
    unittest.main()
