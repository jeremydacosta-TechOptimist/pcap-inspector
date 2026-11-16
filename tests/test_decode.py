"""Tests for the layer-by-layer packet decoder against handcrafted frames."""

from __future__ import annotations

import struct
import unittest

import support

from pcapkit.decode import decode_capture, decode_packet, describe_packet
from pcapkit.models import Capture, CapturedPacket

BASE_TIMESTAMP_NS = 1_700_000_000_000_000_000


def as_packet(data: bytes, *, linktype: int = 1) -> CapturedPacket:
    """Wrap raw frame bytes in a captured packet."""
    return CapturedPacket(
        timestamp_ns=BASE_TIMESTAMP_NS,
        data=data,
        original_length=len(data),
        linktype=linktype,
    )


def decode(data: bytes, *, linktype: int = 1):
    """Decode one handcrafted frame."""
    return decode_packet(as_packet(data, linktype=linktype), 1)


def dns_udp_frame() -> bytes:
    """Build Ethernet/IPv4/UDP/DNS query frame."""
    dns_payload = support.dns_query("www.example.com", 1)
    udp = support.udp_datagram(dns_payload)
    return support.ethernet(support.ipv4_packet(udp, protocol=17))


class EthernetTests(unittest.TestCase):
    """Ethernet, VLAN and unsupported-link handling."""

    def test_ethernet_header_is_decoded(self) -> None:
        packet = decode(support.ethernet(b"\x00" * 10, ethertype=0x88CC))
        assert packet.ethernet is not None
        self.assertEqual(packet.ethernet.destination, "02:00:00:00:00:02")
        self.assertEqual(packet.ethernet.source, "02:00:00:00:00:01")
        self.assertEqual(packet.ethernet.ethertype, 0x88CC)
        self.assertEqual(packet.ethernet.ethertype_name, "LLDP")

    def test_unknown_ethertype_is_reported_honestly(self) -> None:
        packet = decode(support.ethernet(b"\x00" * 10, ethertype=0x88CC))
        self.assertIsNone(packet.ipv4)
        self.assertEqual(packet.errors, [])
        self.assertTrue(any("not decoded" in note for note in packet.notes))
        self.assertIn("EtherType 0x88cc (LLDP)", describe_packet(packet))

    def test_short_frame_does_not_raise(self) -> None:
        packet = decode(b"\x01\x02\x03")
        self.assertIsNone(packet.ethernet)
        self.assertTrue(packet.errors)
        self.assertIn("undecodable frame", describe_packet(packet))

    def test_unsupported_link_type_is_reported(self) -> None:
        packet = decode(b"\x00" * 40, linktype=101)
        self.assertTrue(any("link type 101" in note for note in packet.notes))
        self.assertEqual(packet.protocol_label, "Unknown")

    def test_single_vlan_tag(self) -> None:
        ipv4 = support.ipv4_packet(support.udp_datagram(b"payload"), protocol=17)
        frame = support.vlan_frame(ipv4, [(support.TPID_8021Q, 3, 100)])
        packet = decode(frame)
        self.assertEqual(len(packet.vlans), 1)
        self.assertEqual(packet.vlans[0].vid, 100)
        self.assertEqual(packet.vlans[0].pcp, 3)
        self.assertFalse(packet.vlans[0].dei)
        assert packet.ipv4 is not None
        self.assertEqual(packet.ipv4.source, "192.0.2.10")
        self.assertTrue(describe_packet(packet).startswith("VLAN 100: "))

    def test_qinq_double_tag(self) -> None:
        ipv4 = support.ipv4_packet(support.udp_datagram(b"payload"), protocol=17)
        frame = support.vlan_frame(
            ipv4,
            [(support.TPID_8021AD, 0, 100), (support.TPID_8021Q, 0, 200)],
        )
        packet = decode(frame)
        self.assertEqual([tag.vid for tag in packet.vlans], [100, 200])
        self.assertTrue(describe_packet(packet).startswith("VLAN 100/200: "))
        self.assertIsNotNone(packet.udp)

    def test_truncated_vlan_tag_is_reported(self) -> None:
        frame = support.ethernet(b"\x00\x64\x00", ethertype=0x8100)
        packet = decode(frame)
        self.assertTrue(any("vlan: truncated" in error for error in packet.errors))
        self.assertTrue(packet.truncated)


class ArpTests(unittest.TestCase):
    """ARP decoding."""

    def test_arp_request(self) -> None:
        frame = support.ethernet(
            support.arp_packet(
                operation=1,
                sender_mac="02:00:00:00:00:01",
                sender_ip="192.0.2.10",
                target_ip="192.0.2.20",
            ),
            ethertype=support.ETHERTYPE_ARP,
        )
        packet = decode(frame)
        assert packet.arp is not None
        self.assertEqual(packet.arp.operation, 1)
        self.assertEqual(packet.arp.operation_name, "request")
        self.assertEqual(packet.arp.sender_ip, "192.0.2.10")
        self.assertEqual(packet.arp.sender_mac, "02:00:00:00:00:01")
        self.assertEqual(packet.arp.target_ip, "192.0.2.20")
        self.assertIn("ARP request who-has 192.0.2.20", describe_packet(packet))

    def test_arp_reply(self) -> None:
        frame = support.ethernet(
            support.arp_packet(
                operation=2,
                sender_mac="02:00:00:00:00:02",
                sender_ip="192.0.2.20",
                target_mac="02:00:00:00:00:01",
                target_ip="192.0.2.10",
            ),
            ethertype=support.ETHERTYPE_ARP,
        )
        packet = decode(frame)
        assert packet.arp is not None
        self.assertEqual(packet.arp.operation_name, "reply")
        self.assertIn("ARP reply 192.0.2.20 is-at 02:00:00:00:00:02", describe_packet(packet))

    def test_truncated_arp_is_reported(self) -> None:
        arp_header_only = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        frame = support.ethernet(arp_header_only, ethertype=support.ETHERTYPE_ARP)
        packet = decode(frame)
        self.assertTrue(any("arp: addresses truncated" in error for error in packet.errors))
        self.assertIsNone(packet.arp)


class Ipv4Tests(unittest.TestCase):
    """IPv4 header validation and fragmentation handling."""

    def test_ipv4_udp_dns_stack(self) -> None:
        packet = decode(dns_udp_frame())
        assert packet.ipv4 is not None and packet.udp is not None
        self.assertEqual(packet.ipv4.source, "192.0.2.10")
        self.assertEqual(packet.ipv4.destination, "198.51.100.53")
        self.assertEqual(packet.ipv4.time_to_live, 64)
        self.assertEqual(packet.ipv4.protocol, 17)
        self.assertEqual(packet.ipv4.protocol_name, "UDP")
        self.assertEqual(packet.ipv4.ihl, 5)
        self.assertTrue(packet.ipv4.checksum_valid)
        self.assertEqual(packet.udp.source_port, 49152)
        self.assertEqual(packet.udp.destination_port, 53)
        assert packet.dns is not None
        self.assertEqual(packet.dns.questions[0].name, "www.example.com")
        self.assertIn("DNS query www.example.com A", describe_packet(packet))

    def test_bad_ipv4_checksum_is_detected(self) -> None:
        udp = support.udp_datagram(b"payload", destination_port=9999)
        ipv4 = support.ipv4_packet(udp, protocol=17, checksum_value=0xDEAD)
        packet = decode(support.ethernet(ipv4))
        assert packet.ipv4 is not None
        self.assertFalse(packet.ipv4.checksum_valid)
        self.assertTrue(any("checksum mismatch" in note for note in packet.notes))
        self.assertEqual(packet.errors, [])

    def test_truncated_ipv4_payload_is_reported(self) -> None:
        full = support.ethernet(support.ipv4_packet(support.udp_datagram(b"x" * 30), protocol=17))
        packet = decode(full[:14 + 20 + 5])
        assert packet.ipv4 is not None
        self.assertTrue(packet.truncated)
        self.assertTrue(any("truncated payload" in error for error in packet.errors))
        self.assertIsNone(packet.udp)

    def test_fragmented_first_fragment_keeps_transport(self) -> None:
        udp = support.udp_datagram(b"fragment payload")
        ipv4 = support.ipv4_packet(udp, protocol=17, flags=0x2000)
        packet = decode(support.ethernet(ipv4))
        assert packet.ipv4 is not None
        self.assertTrue(packet.ipv4.more_fragments)
        self.assertTrue(packet.ipv4.fragmented)
        self.assertIsNotNone(packet.udp)
        self.assertTrue(any("fragmented datagram" in note for note in packet.notes))

    def test_later_fragment_has_no_transport_header(self) -> None:
        ipv4 = support.ipv4_packet(b"\x11" * 40, protocol=17, flags=0x0000, fragment_offset=8)
        packet = decode(support.ethernet(ipv4))
        assert packet.ipv4 is not None
        self.assertEqual(packet.ipv4.fragment_offset, 8)
        self.assertIsNone(packet.udp)
        self.assertTrue(any("non-initial fragment" in note for note in packet.notes))

    def test_unknown_ip_protocol_is_noted(self) -> None:
        ipv4 = support.ipv4_packet(b"\x00" * 20, protocol=47)
        packet = decode(support.ethernet(ipv4))
        self.assertIsNone(packet.tcp)
        self.assertTrue(any("GRE" in note for note in packet.notes))
        self.assertEqual(packet.protocol_label, "IPv4/GRE")

    def test_ipv4_header_shorter_than_minimum_is_reported(self) -> None:
        ipv4 = bytearray(support.ipv4_packet(b"", protocol=17))
        ipv4[0] = 0x44  # IHL of 4 words
        packet = decode(support.ethernet(bytes(ipv4)))
        self.assertTrue(packet.errors)
        self.assertIsNone(packet.ipv4)


class TcpTests(unittest.TestCase):
    """TCP segment decoding."""

    def test_syn_segment(self) -> None:
        segment = support.tcp_segment(["SYN"], sequence=1_000, source_port=40000)
        packet = decode(support.ethernet(support.ipv4_packet(segment, protocol=6)))
        assert packet.tcp is not None
        self.assertEqual(packet.tcp.source_port, 40000)
        self.assertEqual(packet.tcp.destination_port, 80)
        self.assertEqual(packet.tcp.flags, ["SYN"])
        self.assertEqual(packet.tcp.sequence, 1_000)
        self.assertEqual(packet.tcp.payload_length, 0)
        self.assertEqual(packet.tcp.header_length, 20)
        self.assertIn("[SYN]", describe_packet(packet))

    def test_syn_ack_and_payload_length(self) -> None:
        segment = support.tcp_segment(
            ["SYN", "ACK"], payload=b"GET / HTTP/1.1\r\n\r\n", acknowledgement=42
        )
        packet = decode(
            support.ethernet(support.ipv4_packet(segment, protocol=6))
        )
        assert packet.tcp is not None
        self.assertEqual(packet.tcp.flags, ["SYN", "ACK"])
        self.assertEqual(packet.tcp.acknowledgement, 42)
        self.assertEqual(packet.tcp.payload_length, len(b"GET / HTTP/1.1\r\n\r\n"))

    def test_truncated_tcp_header_is_reported(self) -> None:
        segment = support.tcp_segment(["ACK"])[:12]
        packet = decode(support.ethernet(support.ipv4_packet(segment, protocol=6)))
        self.assertTrue(packet.errors)
        self.assertIsNone(packet.tcp)


class UdpTests(unittest.TestCase):
    """UDP decoding and DNS dispatch."""

    def test_non_dns_udp(self) -> None:
        udp = support.udp_datagram(
            b"hello", source_port=5353, destination_port=5353
        )
        packet = decode(support.ethernet(support.ipv4_packet(udp, protocol=17)))
        assert packet.udp is not None
        self.assertEqual(packet.udp.length, 8 + 5)
        self.assertEqual(packet.udp.payload_length, 5)
        self.assertIsNone(packet.dns)
        self.assertIn("UDP 192.0.2.10:5353 -> 198.51.100.53:5353", describe_packet(packet))

    def test_malformed_dns_payload_is_reported(self) -> None:
        udp = support.udp_datagram(b"\x00\x01\x02")
        packet = decode(support.ethernet(support.ipv4_packet(udp, protocol=17)))
        self.assertIsNone(packet.dns)
        self.assertTrue(any(error.startswith("dns:") for error in packet.errors))

    def test_dns_response_over_udp_is_decoded(self) -> None:
        response = support.dns_response(
            "www.example.com",
            1,
            [
                (
                    support.QUESTION_POINTER,
                    1,
                    300,
                    support.ip4("203.0.113.10"),
                )
            ],
        )
        udp = support.udp_datagram(
            response,
            source="198.51.100.53",
            destination="192.0.2.10",
            source_port=53,
            destination_port=49152,
        )
        frame = support.ethernet(
            support.ipv4_packet(
                udp, source="198.51.100.53", destination="192.0.2.10", protocol=17
            )
        )
        packet = decode(frame)
        assert packet.dns is not None
        self.assertTrue(packet.dns.is_response)
        self.assertEqual(packet.dns.answers[0].value, "203.0.113.10")
        self.assertIn("DNS response", describe_packet(packet))


class IcmpTests(unittest.TestCase):
    """ICMP and ICMPv6 decoding."""

    def test_icmp_echo_request(self) -> None:
        frame = support.ethernet(
            support.ipv4_packet(support.icmp_echo(identifier=7, sequence=3), protocol=1)
        )
        packet = decode(frame)
        assert packet.icmp is not None
        self.assertEqual(packet.icmp.type, 8)
        self.assertEqual(packet.icmp.type_name, "echo request")
        self.assertEqual(packet.icmp.echo_id, 7)
        self.assertEqual(packet.icmp.echo_sequence, 3)
        self.assertEqual(packet.icmp.payload_length, 16)
        self.assertIn("ICMP echo request id=7 seq=3", describe_packet(packet))

    def test_icmp_echo_reply(self) -> None:
        frame = support.ethernet(
            support.ipv4_packet(support.icmp_echo(identifier=7, sequence=3, request=False), protocol=1)
        )
        packet = decode(frame)
        assert packet.icmp is not None
        self.assertEqual(packet.icmp.type_name, "echo reply")

    def test_icmpv6_echo_request(self) -> None:
        icmpv6 = support.icmpv6_echo(identifier=2, sequence=1)
        frame = support.ethernet(
            support.ipv6_packet(icmpv6, next_header=58), ethertype=support.ETHERTYPE_IPV6
        )
        packet = decode(frame)
        assert packet.icmpv6 is not None and packet.ipv6 is not None
        self.assertEqual(packet.icmpv6.type, 128)
        self.assertEqual(packet.icmpv6.type_name, "echo request")
        self.assertEqual(packet.icmpv6.echo_id, 2)
        self.assertIn("ICMPv6 echo request id=2 seq=1", describe_packet(packet))


class Ipv6Tests(unittest.TestCase):
    """IPv6 decoding including the next-header chain."""

    def test_ipv6_udp(self) -> None:
        udp = support.udp_datagram(
            b"payload",
            source="2001:db8::10",
            destination="2001:db8::53",
            source_port=5353,
            destination_port=9999,
            ip_version=6,
        )
        frame = support.ethernet(
            support.ipv6_packet(
                udp,
                source="2001:db8::10",
                destination="2001:db8::53",
                next_header=17,
            ),
            ethertype=support.ETHERTYPE_IPV6,
        )
        packet = decode(frame)
        assert packet.ipv6 is not None and packet.udp is not None
        self.assertEqual(packet.ipv6.source, "2001:db8::10")
        self.assertEqual(packet.ipv6.destination, "2001:db8::53")
        self.assertEqual(packet.ipv6.transport_next_header, 17)
        self.assertEqual(packet.ipv6.extension_headers, [])
        self.assertIn("[2001:db8::10]:5353", describe_packet(packet))

    def test_extension_header_chain_is_walked(self) -> None:
        hop_by_hop = bytes([17, 0]) + b"\x00" * 6  # next header UDP, 8-byte header
        udp = support.udp_datagram(
            b"payload",
            source="2001:db8::10",
            destination="2001:db8::53",
            ip_version=6,
        )
        frame = support.ethernet(
            support.ipv6_packet(hop_by_hop + udp, next_header=0),
            ethertype=support.ETHERTYPE_IPV6,
        )
        packet = decode(frame)
        assert packet.ipv6 is not None
        self.assertEqual(packet.ipv6.extension_headers, [0])
        self.assertEqual(packet.ipv6.transport_next_header, 17)
        self.assertIsNotNone(packet.udp)

    def test_ipv6_dns_is_decoded(self) -> None:
        dns_payload = support.dns_query("api.example.net", 28)
        udp = support.udp_datagram(
            dns_payload,
            source="2001:db8::10",
            destination="2001:db8::53",
            ip_version=6,
        )
        frame = support.ethernet(
            support.ipv6_packet(udp, next_header=17), ethertype=support.ETHERTYPE_IPV6
        )
        packet = decode(frame)
        assert packet.dns is not None
        self.assertEqual(packet.dns.questions[0].qtype_name, "AAAA")


class DecodeCaptureTests(unittest.TestCase):
    """The capture-level decoder wrapper."""

    def test_decode_capture_keeps_order_and_indexes(self) -> None:
        frame = dns_udp_frame()
        capture = Capture(
            source="fixture.pcap",
            format="pcap",
            byte_order="little",
            version="2.4",
            snaplen=65535,
            linktype=1,
            packets=[
                as_packet(frame),
                CapturedPacket(timestamp_ns=BASE_TIMESTAMP_NS + 1, data=frame, original_length=len(frame)),
            ],
        )
        decoded = decode_capture(capture)
        self.assertEqual([packet.index for packet in decoded], [1, 2])
        self.assertEqual(len(decoded), 2)
        assert decoded[0].dns is not None
        self.assertEqual(decoded[0].dns.questions[0].name, "www.example.com")


if __name__ == "__main__":
    unittest.main()
