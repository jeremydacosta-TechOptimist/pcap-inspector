"""Compact DNS decoder (RFC 1035) for UDP port 53 traffic.

The decoder covers the header, the question section and the answer section of
query and response messages, including compressed names.  It deliberately does
not attempt to reassemble DNS over TCP, and zone transfers are not decoded.
"""

from __future__ import annotations

import ipaddress
import struct

from .errors import DnsDecodeError
from .models import DnsMessage, DnsQuestion, DnsRecord

HEADER_LENGTH = 12
MAX_COMPRESSION_JUMPS = 64
MAX_NAME_LENGTH = 255
MAX_QUESTIONS = 16
MAX_ANSWERS = 64

RECORD_A = 1
RECORD_NS = 2
RECORD_CNAME = 5
RECORD_PTR = 12
RECORD_MX = 15
RECORD_TXT = 16
RECORD_AAAA = 28


def decode_message(data: bytes) -> DnsMessage:
    """Decode a DNS message from raw bytes.

    Raises :class:`DnsDecodeError` when the payload is not a well-formed DNS
    message; the packet decoder catches it and records the error on the packet.
    """
    if len(data) < HEADER_LENGTH:
        raise DnsDecodeError(
            f"message is {len(data)} bytes, shorter than the {HEADER_LENGTH}-byte header"
        )
    transaction_id, flags, question_count, answer_count, _authority_count, _additional_count = (
        struct.unpack("!HHHHHH", data[:HEADER_LENGTH])
    )
    if question_count > MAX_QUESTIONS:
        raise DnsDecodeError(
            f"question count {question_count} exceeds the supported limit {MAX_QUESTIONS}"
        )
    if answer_count > MAX_ANSWERS:
        raise DnsDecodeError(
            f"answer count {answer_count} exceeds the supported limit {MAX_ANSWERS}"
        )

    message = DnsMessage(
        transaction_id=transaction_id,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        authoritative=bool(flags & 0x0400),
        truncated=bool(flags & 0x0200),
        recursion_desired=bool(flags & 0x0100),
        recursion_available=bool(flags & 0x0080),
        rcode=flags & 0x000F,
    )

    offset = HEADER_LENGTH
    for _ in range(question_count):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DnsDecodeError("truncated DNS question section")
        query_type, query_class = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        message.questions.append(
            DnsQuestion(name=name, qtype=query_type, qclass=query_class)
        )

    for _ in range(answer_count):
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise DnsDecodeError("truncated DNS answer header")
        record_type, _record_class, time_to_live, rdata_length = struct.unpack(
            "!HHIH", data[offset : offset + 10]
        )
        offset += 10
        rdata_end = offset + rdata_length
        if rdata_end > len(data):
            raise DnsDecodeError("truncated DNS answer data")
        value = _format_rdata(data, offset, rdata_length, record_type)
        message.answers.append(
            DnsRecord(name=name, rtype=record_type, ttl=time_to_live, value=value)
        )
        offset = rdata_end

    return message


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly compressed DNS name.

    Returns the presentation-format name and the offset immediately after the
    name in the original byte sequence (not after the compression target).
    """
    labels: list[str] = []
    position = offset
    resume_offset: int | None = None
    jumps = 0
    encoded_length = 0

    while True:
        if position >= len(data):
            raise DnsDecodeError("truncated DNS name")
        length_byte = data[position]

        if length_byte & 0xC0 == 0xC0:
            if position + 1 >= len(data):
                raise DnsDecodeError("truncated DNS compression pointer")
            pointer = ((length_byte & 0x3F) << 8) | data[position + 1]
            if resume_offset is None:
                resume_offset = position + 2
            jumps += 1
            if jumps > MAX_COMPRESSION_JUMPS:
                raise DnsDecodeError("DNS compression pointer chain is too long (possible loop)")
            if pointer >= len(data):
                raise DnsDecodeError(
                    f"DNS compression pointer {pointer} points outside the message"
                )
            position = pointer
            continue

        if length_byte & 0xC0:
            raise DnsDecodeError(f"invalid DNS label length byte 0x{length_byte:02x}")

        position += 1
        if length_byte == 0:
            if resume_offset is None:
                resume_offset = position
            break

        label_bytes = data[position : position + length_byte]
        if len(label_bytes) < length_byte:
            raise DnsDecodeError("truncated DNS label")
        labels.append(label_bytes.decode("ascii", "backslashreplace"))
        encoded_length += length_byte + 1
        if encoded_length > MAX_NAME_LENGTH:
            raise DnsDecodeError("DNS name is longer than 255 bytes")
        position += length_byte

    name = ".".join(labels) if labels else "."
    return name, resume_offset


def _format_rdata(data: bytes, offset: int, length: int, record_type: int) -> str:
    """Format the RDATA of one answer record in presentation format."""
    rdata = data[offset : offset + length]
    if record_type == RECORD_A:
        if length != 4:
            return f"malformed A record ({length} bytes)"
        return str(ipaddress.IPv4Address(rdata))
    if record_type == RECORD_AAAA:
        if length != 16:
            return f"malformed AAAA record ({length} bytes)"
        return str(ipaddress.IPv6Address(rdata))
    if record_type in (RECORD_CNAME, RECORD_NS, RECORD_PTR):
        try:
            name, _next_offset = decode_name(data, offset)
        except DnsDecodeError:
            return f"malformed {record_type} record"
        return name
    if record_type == RECORD_MX:
        if length < 3:
            return f"malformed MX record ({length} bytes)"
        preference = struct.unpack("!H", rdata[:2])[0]
        try:
            exchange, _next_offset = decode_name(data, offset + 2)
        except DnsDecodeError:
            return f"malformed MX record (preference {preference})"
        return f"{preference} {exchange}"
    if record_type == RECORD_TXT:
        return _format_txt(rdata)
    if not rdata:
        return "<empty>"
    hexadecimal = rdata.hex()
    if len(hexadecimal) > 64:
        hexadecimal = hexadecimal[:64] + "..."
    return f"0x{hexadecimal}"


def _format_txt(rdata: bytes) -> str:
    """Decode the length-prefixed strings inside a TXT record."""
    pieces: list[str] = []
    position = 0
    while position < len(rdata):
        text_length = rdata[position]
        position += 1
        chunk = rdata[position : position + text_length]
        if len(chunk) < text_length:
            return "malformed TXT record"
        pieces.append(chunk.decode("utf-8", "replace"))
        position += text_length
    return " ".join(pieces)
