"""Synthetic demo capture used by the ``pcapkit demo`` command.

The traffic is deterministic and built entirely with the standard library, so
the README demo needs no external capture file.  The lab topology is documented
below; every frame is a well-formed Ethernet II frame on link type 1.

Lab topology (documentation address ranges only):

* ``192.0.2.0/24``   local LAN, default gateway ``192.0.2.1``
* ``198.51.100.0/24`` services network (DNS authoritative server)
* ``203.0.113.0/24`` remote network (web and TLS servers)
* ``2001:db8::/32``  IPv6 lab network
"""

from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone

from .models import Capture, CapturedPacket, InterfaceInfo
from .pcap import write_pcap
from .util import internet_checksum

DEMO_SNAPLEN = 65535
DEMO_LINKTYPE = 1
BASE_TIMESTAMP_NS = (
    int(datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
)

MAC_GATEWAY = "02:00:00:00:00:01"
MAC_CLIENT = "02:00:00:00:00:0a"
MAC_CLIENT2 = "02:00:00:00:00:1e"
MAC_SERVER = "02:00:00:00:00:14"
MAC_IPV6_CLIENT = "02:00:00:00:00:0b"
MAC_IPV6_SERVER = "02:00:00:00:00:15"
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"

CLIENT = "192.0.2.10"
SERVER = "192.0.2.20"
CLIENT2 = "192.0.2.30"
DNS_SERVER = "198.51.100.53"
WEB_SERVER = "198.51.100.80"
TLS_SERVER = "203.0.113.50"
IPV6_CLIENT = "2001:db8::10"
IPV6_SERVER = "2001:db8::20"
IPV6_DNS_SERVER = "2001:db8::53"

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
TPID_8021Q = 0x8100
TPID_8021AD = 0x88A8

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

DNS_RECORD_A = 1
DNS_RECORD_CNAME = 5
DNS_RECORD_MX = 15
DNS_RECORD_AAAA = 28

TCP_FLAG_BITS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}

_HTTP_GET = (
    b"GET /status HTTP/1.1\r\n"
    b"Host: web.example.net\r\n"
    b"User-Agent: pcapkit-demo/1.0\r\n"
    b"Accept: */*\r\n\r\n"
)
_HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 61\r\n"
    b'Connection: close\r\n\r\n'
    b'{"status": "ok", "host": "web.example.net", "region": "lab"}'
)
_ICMP_PAYLOAD = b"pcapkit demo icmp echo payload!"
_ICMPV6_PAYLOAD = b"pcapkit demo icmpv6 echo payload"


def _hardware_address(text: str) -> bytes:
    """Convert a colon-separated MAC address to six bytes."""
    return bytes.fromhex(text.replace(":", ""))


def _ipv4_bytes(text: str) -> bytes:
    """Convert a dotted-quad IPv4 address to four bytes."""
    return socket.inet_pton(socket.AF_INET, text)


def _ipv6_bytes(text: str) -> bytes:
    """Convert an IPv6 address to sixteen bytes."""
    return socket.inet_pton(socket.AF_INET6, text)


def ethernet_frame(destination: str, source: str, ethertype: int, payload: bytes) -> bytes:
    """Build an untagged Ethernet II frame around ``payload``."""
    return (
        _hardware_address(destination)
        + _hardware_address(source)
        + struct.pack("!H", ethertype)
        + payload
    )


def vlan_frame(
    destination: str,
    source: str,
    tags: list[tuple[int, int, int]],
    ethertype: int,
    payload: bytes,
) -> bytes:
    """Build an Ethernet frame with one or more stacked 802.1Q tags.

    ``tags`` contains ``(tpid, pcp, vid)`` tuples from the outermost tag inwards,
    so two tuples produce a QinQ frame.
    """
    header = _hardware_address(destination) + _hardware_address(source)
    for tpid, pcp, vid in tags:
        header += struct.pack("!HH", tpid, (pcp << 13) | vid)
    header += struct.pack("!H", ethertype)
    return header + payload


def arp_packet(
    operation: int,
    sender_mac: str,
    sender_ip: str,
    target_mac: str,
    target_ip: str,
) -> bytes:
    """Build an Ethernet/IPv4 ARP packet body (operation 1 request, 2 reply)."""
    return (
        struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, operation)
        + _hardware_address(sender_mac)
        + _ipv4_bytes(sender_ip)
        + _hardware_address(target_mac)
        + _ipv4_bytes(target_ip)
    )


def ipv4_packet(
    source: str,
    destination: str,
    protocol: int,
    payload: bytes,
    *,
    time_to_live: int = 64,
    identification: int = 0,
    flags: int = 0x4000,
    fragment_offset: int = 0,
) -> bytes:
    """Build an IPv4 packet with a correct header checksum."""
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        flags | (fragment_offset // 8),
        time_to_live,
        protocol,
        0,
        _ipv4_bytes(source),
        _ipv4_bytes(destination),
    )
    checksum = internet_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def ipv6_packet(
    source: str,
    destination: str,
    next_header: int,
    payload: bytes,
    *,
    hop_limit: int = 64,
    traffic_class: int = 0,
    flow_label: int = 0,
) -> bytes:
    """Build an IPv6 packet without extension headers."""
    first_word = (6 << 28) | (traffic_class << 20) | flow_label
    header = (
        struct.pack("!IHBB", first_word, len(payload), next_header, hop_limit)
        + _ipv6_bytes(source)
        + _ipv6_bytes(destination)
    )
    return header + payload


def _pseudo_header(
    source: str, destination: str, protocol: int, length: int, ip_version: int
) -> bytes:
    """Build the TCP/UDP/ICMPv6 pseudo header used for checksum computation."""
    if ip_version == 4:
        return (
            _ipv4_bytes(source)
            + _ipv4_bytes(destination)
            + struct.pack("!BBH", 0, protocol, length)
        )
    return (
        _ipv6_bytes(source)
        + _ipv6_bytes(destination)
        + struct.pack("!I3xB", length, protocol)
    )


def tcp_segment(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: list[str],
    payload: bytes = b"",
    *,
    window: int = 64240,
    ip_version: int = 4,
) -> bytes:
    """Build a TCP segment with a correct checksum."""
    flag_byte = 0
    for flag in flags:
        flag_byte |= TCP_FLAG_BITS[flag]
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
    checksum = internet_checksum(
        _pseudo_header(source, destination, IPPROTO_TCP, len(header) + len(payload), ip_version)
        + header
        + payload
    )
    header = header[:16] + struct.pack("!H", checksum) + header[18:]
    return header + payload


def udp_datagram(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
    *,
    ip_version: int = 4,
) -> bytes:
    """Build a UDP datagram with a correct checksum."""
    length = 8 + len(payload)
    base = struct.pack("!HHHH", source_port, destination_port, length, 0)
    checksum = internet_checksum(
        _pseudo_header(source, destination, IPPROTO_UDP, length, ip_version) + base + payload
    )
    if checksum == 0:
        checksum = 0xFFFF  # a transmitted zero means "no checksum"
    return struct.pack("!HHHH", source_port, destination_port, length, checksum) + payload


def icmp_echo(identifier: int, sequence: int, *, request: bool = True) -> bytes:
    """Build an IPv4 ICMP echo request or reply."""
    message_type = 8 if request else 0
    header = struct.pack("!BBHHH", message_type, 0, 0, identifier, sequence)
    checksum = internet_checksum(header + _ICMP_PAYLOAD)
    return header[:2] + struct.pack("!H", checksum) + header[4:] + _ICMP_PAYLOAD


def icmpv6_echo(
    source: str, destination: str, identifier: int, sequence: int, *, request: bool = True
) -> bytes:
    """Build an IPv6 ICMPv6 echo request or reply."""
    message_type = 128 if request else 129
    header = struct.pack("!BBHHH", message_type, 0, 0, identifier, sequence)
    payload = _ICMPV6_PAYLOAD
    checksum = internet_checksum(
        _pseudo_header(
            source, destination, IPPROTO_ICMPV6, len(header) + len(payload), 6
        )
        + header
        + payload
    )
    return header[:2] + struct.pack("!H", checksum) + header[4:] + payload


def _dns_name(name: str) -> bytes:
    """Encode a DNS name as a sequence of length-prefixed labels."""
    encoded = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("ascii")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def dns_query(transaction_id: int, name: str, query_type: int) -> bytes:
    """Build a recursive DNS query message."""
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + _dns_name(name) + struct.pack("!HH", query_type, 1)


def dns_response(
    transaction_id: int,
    name: str,
    query_type: int,
    answers: list[tuple[bytes, int, int, bytes]],
    *,
    rcode: int = 0,
) -> bytes:
    """Build a DNS response message with the given answer records.

    Each answer is ``(encoded_name, record_type, ttl, rdata)``; pass
    :data:`DNS_QUESTION_POINTER` as the encoded name to compress it to the
    question name.
    """
    flags = 0x8180 | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, len(answers), 0, 0)
    question = _dns_name(name) + struct.pack("!HH", query_type, 1)
    body = b""
    for encoded_name, record_type, time_to_live, rdata in answers:
        body += (
            encoded_name
            + struct.pack("!HHIH", record_type, 1, time_to_live, len(rdata))
            + rdata
        )
    return header + question + body


DNS_QUESTION_POINTER = b"\xc0\x0c"
DNS_TTL = 300


def build_demo_capture() -> Capture:
    """Build the deterministic synthetic capture used by the demo command."""
    packets: list[CapturedPacket] = []

    def add(offset_microseconds: int, frame: bytes) -> None:
        packets.append(
            CapturedPacket(
                timestamp_ns=BASE_TIMESTAMP_NS + offset_microseconds * 1_000,
                data=frame,
                original_length=len(frame),
                interface_id=0,
                linktype=DEMO_LINKTYPE,
            )
        )

    # 1-2: ARP resolution of the local server before the ICMP test.
    add(
        0,
        ethernet_frame(
            MAC_BROADCAST,
            MAC_CLIENT,
            ETHERTYPE_ARP,
            arp_packet(1, MAC_CLIENT, CLIENT, "00:00:00:00:00:00", SERVER),
        ),
    )
    add(
        950,
        ethernet_frame(
            MAC_CLIENT,
            MAC_SERVER,
            ETHERTYPE_ARP,
            arp_packet(2, MAC_SERVER, SERVER, MAC_CLIENT, CLIENT),
        ),
    )

    # 3-4: DNS lookup www.example.com (CNAME chain) resolved by 198.51.100.53.
    dns_query_id = 0x1A2B
    add(
        3200,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT,
                DNS_SERVER,
                IPPROTO_UDP,
                udp_datagram(CLIENT, DNS_SERVER, 49152, 53, dns_query(dns_query_id, "www.example.com", DNS_RECORD_A)),
            ),
        ),
    )
    add(
        55150,
        ethernet_frame(
            MAC_CLIENT,
            MAC_GATEWAY,
            ETHERTYPE_IPV4,
            ipv4_packet(
                DNS_SERVER,
                CLIENT,
                IPPROTO_UDP,
                udp_datagram(
                    DNS_SERVER,
                    CLIENT,
                    53,
                    49152,
                    dns_response(
                        dns_query_id,
                        "www.example.com",
                        DNS_RECORD_A,
                        [
                            (
                                DNS_QUESTION_POINTER,
                                DNS_RECORD_CNAME,
                                DNS_TTL,
                                _dns_name("example.com"),
                            ),
                            (
                                _dns_name("example.com"),
                                DNS_RECORD_A,
                                DNS_TTL,
                                socket.inet_pton(socket.AF_INET, "203.0.113.10"),
                            ),
                        ],
                    ),
                ),
                time_to_live=56,
            ),
        ),
    )

    # 5-14: HTTP conversation 192.0.2.10:49876 <-> 198.51.100.80:80.
    client_isn = 3_000_000_001
    server_isn = 2_000_000_001
    add(
        120400,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT,
                WEB_SERVER,
                IPPROTO_TCP,
                tcp_segment(CLIENT, WEB_SERVER, 49876, 80, client_isn, 0, ["SYN"]),
            ),
        ),
    )
    add(
        170900,
        ethernet_frame(
            MAC_CLIENT,
            MAC_GATEWAY,
            ETHERTYPE_IPV4,
            ipv4_packet(
                WEB_SERVER,
                CLIENT,
                IPPROTO_TCP,
                tcp_segment(WEB_SERVER, CLIENT, 80, 49876, server_isn, client_isn + 1, ["SYN", "ACK"]),
                time_to_live=56,
            ),
        ),
    )
    add(
        172100,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT,
                WEB_SERVER,
                IPPROTO_TCP,
                tcp_segment(CLIENT, WEB_SERVER, 49876, 80, client_isn + 1, server_isn + 1, ["ACK"]),
            ),
        ),
    )
    add(
        174300,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT,
                WEB_SERVER,
                IPPROTO_TCP,
                tcp_segment(
                    CLIENT,
                    WEB_SERVER,
                    49876,
                    80,
                    client_isn + 1,
                    server_isn + 1,
                    ["PSH", "ACK"],
                    _HTTP_GET,
                ),
            ),
        ),
    )
    client_next_sequence = client_isn + 1 + len(_HTTP_GET)
    add(
        231800,
        ethernet_frame(
            MAC_CLIENT,
            MAC_GATEWAY,
            ETHERTYPE_IPV4,
            ipv4_packet(
                WEB_SERVER,
                CLIENT,
                IPPROTO_TCP,
                tcp_segment(
                    WEB_SERVER,
                    CLIENT,
                    80,
                    49876,
                    server_isn + 1,
                    client_next_sequence,
                    ["PSH", "ACK"],
                    _HTTP_RESPONSE,
                ),
                time_to_live=56,
            ),
        ),
    )
    server_next_sequence = server_isn + 1 + len(_HTTP_RESPONSE)
    add(
        233000,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT,
                WEB_SERVER,
                IPPROTO_TCP,
                tcp_segment(
                    CLIENT,
                    WEB_SERVER,
                    49876,
                    80,
                    client_next_sequence,
                    server_next_sequence,
                    ["ACK"],
                ),
            ),
        ),
    )
    add(
        240500,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT,
                WEB_SERVER,
                IPPROTO_TCP,
                tcp_segment(
                    CLIENT,
                    WEB_SERVER,
                    49876,
                    80,
                    client_next_sequence,
                    server_next_sequence,
                    ["FIN", "ACK"],
                ),
            ),
        ),
    )
    add(
        241200,
        ethernet_frame(
            MAC_CLIENT,
            MAC_GATEWAY,
            ETHERTYPE_IPV4,
            ipv4_packet(
                WEB_SERVER,
                CLIENT,
                IPPROTO_TCP,
                tcp_segment(
                    WEB_SERVER,
                    CLIENT,
                    80,
                    49876,
                    server_next_sequence,
                    client_next_sequence + 1,
                    ["ACK"],
                ),
                time_to_live=56,
            ),
        ),
    )
    add(
        242800,
        ethernet_frame(
            MAC_CLIENT,
            MAC_GATEWAY,
            ETHERTYPE_IPV4,
            ipv4_packet(
                WEB_SERVER,
                CLIENT,
                IPPROTO_TCP,
                tcp_segment(
                    WEB_SERVER,
                    CLIENT,
                    80,
                    49876,
                    server_next_sequence,
                    client_next_sequence + 1,
                    ["FIN", "ACK"],
                ),
                time_to_live=56,
            ),
        ),
    )
    add(
        243400,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT,
                WEB_SERVER,
                IPPROTO_TCP,
                tcp_segment(
                    CLIENT,
                    WEB_SERVER,
                    49876,
                    80,
                    client_next_sequence + 1,
                    server_next_sequence + 1,
                    ["ACK"],
                ),
            ),
        ),
    )

    # 15-16: ICMP echo between two local hosts.
    add(
        300000,
        ethernet_frame(
            MAC_SERVER,
            MAC_CLIENT2,
            ETHERTYPE_IPV4,
            ipv4_packet(CLIENT2, SERVER, IPPROTO_ICMP, icmp_echo(1, 1, request=True)),
        ),
    )
    add(
        300950,
        ethernet_frame(
            MAC_CLIENT2,
            MAC_SERVER,
            ETHERTYPE_IPV4,
            ipv4_packet(SERVER, CLIENT2, IPPROTO_ICMP, icmp_echo(1, 1, request=False)),
        ),
    )

    # 17-18: 802.1Q tagged DNS lookup on VLAN 100 (api.example.net A records).
    vlan_dns_id = 0x3C4D
    add(
        400200,
        vlan_frame(
            MAC_GATEWAY,
            MAC_CLIENT2,
            [(TPID_8021Q, 0, 100)],
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT2,
                DNS_SERVER,
                IPPROTO_UDP,
                udp_datagram(CLIENT2, DNS_SERVER, 5353, 53, dns_query(vlan_dns_id, "api.example.net", DNS_RECORD_A)),
            ),
        ),
    )
    add(
        415700,
        vlan_frame(
            MAC_CLIENT2,
            MAC_GATEWAY,
            [(TPID_8021Q, 0, 100)],
            ETHERTYPE_IPV4,
            ipv4_packet(
                DNS_SERVER,
                CLIENT2,
                IPPROTO_UDP,
                udp_datagram(
                    DNS_SERVER,
                    CLIENT2,
                    53,
                    5353,
                    dns_response(
                        vlan_dns_id,
                        "api.example.net",
                        DNS_RECORD_A,
                        [
                            (
                                DNS_QUESTION_POINTER,
                                DNS_RECORD_A,
                                DNS_TTL,
                                socket.inet_pton(socket.AF_INET, "203.0.113.20"),
                            ),
                            (
                                DNS_QUESTION_POINTER,
                                DNS_RECORD_A,
                                DNS_TTL,
                                socket.inet_pton(socket.AF_INET, "203.0.113.21"),
                            ),
                        ],
                    ),
                ),
                time_to_live=56,
            ),
        ),
    )

    # 19-20: QinQ frame (outer VLAN 100, inner VLAN 200) with an MX query.
    qinq_dns_id = 0x5E6F
    add(
        500300,
        vlan_frame(
            MAC_GATEWAY,
            MAC_SERVER,
            [(TPID_8021AD, 0, 100), (TPID_8021Q, 0, 200)],
            ETHERTYPE_IPV4,
            ipv4_packet(
                SERVER,
                DNS_SERVER,
                IPPROTO_UDP,
                udp_datagram(SERVER, DNS_SERVER, 49153, 53, dns_query(qinq_dns_id, "mail.example.org", DNS_RECORD_MX)),
            ),
        ),
    )
    add(
        530900,
        vlan_frame(
            MAC_SERVER,
            MAC_GATEWAY,
            [(TPID_8021AD, 0, 100), (TPID_8021Q, 0, 200)],
            ETHERTYPE_IPV4,
            ipv4_packet(
                DNS_SERVER,
                SERVER,
                IPPROTO_UDP,
                udp_datagram(
                    DNS_SERVER,
                    SERVER,
                    53,
                    49153,
                    dns_response(
                        qinq_dns_id,
                        "mail.example.org",
                        DNS_RECORD_MX,
                        [
                            (
                                DNS_QUESTION_POINTER,
                                DNS_RECORD_MX,
                                DNS_TTL,
                                struct.pack("!H", 10) + _dns_name("mail.example.org"),
                            )
                        ],
                    ),
                ),
                time_to_live=56,
            ),
        ),
    )

    # 21-22: ICMPv6 echo over IPv6.
    add(
        600100,
        ethernet_frame(
            MAC_IPV6_SERVER,
            MAC_IPV6_CLIENT,
            ETHERTYPE_IPV6,
            ipv6_packet(
                IPV6_CLIENT,
                IPV6_SERVER,
                IPPROTO_ICMPV6,
                icmpv6_echo(IPV6_CLIENT, IPV6_SERVER, 2, 1, request=True),
            ),
        ),
    )
    add(
        601050,
        ethernet_frame(
            MAC_IPV6_CLIENT,
            MAC_IPV6_SERVER,
            ETHERTYPE_IPV6,
            ipv6_packet(
                IPV6_SERVER,
                IPV6_CLIENT,
                IPPROTO_ICMPV6,
                icmpv6_echo(IPV6_SERVER, IPV6_CLIENT, 2, 1, request=False),
            ),
        ),
    )

    # 23-24: DNS AAAA lookup over IPv6 to 2001:db8::53.
    ipv6_dns_id = 0x7788
    add(
        650400,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_IPV6_CLIENT,
            ETHERTYPE_IPV6,
            ipv6_packet(
                IPV6_CLIENT,
                IPV6_DNS_SERVER,
                IPPROTO_UDP,
                udp_datagram(
                    IPV6_CLIENT,
                    IPV6_DNS_SERVER,
                    49154,
                    53,
                    dns_query(ipv6_dns_id, "api.example.net", DNS_RECORD_AAAA),
                    ip_version=6,
                ),
            ),
        ),
    )
    add(
        680950,
        ethernet_frame(
            MAC_IPV6_CLIENT,
            MAC_GATEWAY,
            ETHERTYPE_IPV6,
            ipv6_packet(
                IPV6_DNS_SERVER,
                IPV6_CLIENT,
                IPPROTO_UDP,
                udp_datagram(
                    IPV6_DNS_SERVER,
                    IPV6_CLIENT,
                    53,
                    49154,
                    dns_response(
                        ipv6_dns_id,
                        "api.example.net",
                        DNS_RECORD_AAAA,
                        [
                            (
                                DNS_QUESTION_POINTER,
                                DNS_RECORD_AAAA,
                                DNS_TTL,
                                socket.inet_pton(socket.AF_INET6, "2001:db8:100::20"),
                            )
                        ],
                    ),
                    ip_version=6,
                ),
                hop_limit=63,
            ),
        ),
    )

    # 25-27: TLS handshake to 203.0.113.50:443 (SYN, SYN-ACK, ACK).
    add(
        700100,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT2,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT2,
                TLS_SERVER,
                IPPROTO_TCP,
                tcp_segment(CLIENT2, TLS_SERVER, 50000, 443, 1_500_000_001, 0, ["SYN"]),
            ),
        ),
    )
    add(
        750600,
        ethernet_frame(
            MAC_CLIENT2,
            MAC_GATEWAY,
            ETHERTYPE_IPV4,
            ipv4_packet(
                TLS_SERVER,
                CLIENT2,
                IPPROTO_TCP,
                tcp_segment(
                    TLS_SERVER,
                    CLIENT2,
                    443,
                    50000,
                    3_500_000_001,
                    1_500_000_002,
                    ["SYN", "ACK"],
                ),
                time_to_live=56,
            ),
        ),
    )
    add(
        751300,
        ethernet_frame(
            MAC_GATEWAY,
            MAC_CLIENT2,
            ETHERTYPE_IPV4,
            ipv4_packet(
                CLIENT2,
                TLS_SERVER,
                IPPROTO_TCP,
                tcp_segment(CLIENT2, TLS_SERVER, 50000, 443, 1_500_000_002, 3_500_000_002, ["ACK"]),
            ),
        ),
    )

    interfaces = [InterfaceInfo(index=0, linktype=DEMO_LINKTYPE, snaplen=DEMO_SNAPLEN)]
    return Capture(
        source="demo.pcap",
        format="pcap",
        byte_order="little",
        version="2.4",
        snaplen=DEMO_SNAPLEN,
        linktype=DEMO_LINKTYPE,
        packets=packets,
        interfaces=interfaces,
        warnings=[],
    )


def write_demo_capture(path: str) -> Capture:
    """Build the demo capture and write it as a little-endian pcap file."""
    capture = build_demo_capture()
    write_pcap(
        path,
        capture.packets,
        linktype=DEMO_LINKTYPE,
        snaplen=DEMO_SNAPLEN,
        byte_order="little",
        nanosecond=False,
    )
    return capture
