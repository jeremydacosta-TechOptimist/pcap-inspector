"""Capture file format detection and unified reading.

A capture is loaded fully into memory: pcapkit is an analysis tool for captures
of a practical size, not a streaming collector.
"""

from __future__ import annotations

from pathlib import Path

from .errors import PcapError
from .models import Capture
from .pcap import PCAP_MAGICS, parse_pcap
from .pcapng import SHB_BYTES, parse_pcapng


def read_capture(path: str | Path) -> Capture:
    """Read a pcap or pcapng capture from disk, detecting the format by magic."""
    source = Path(path).name
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PcapError(f"cannot read {source}: {exc}") from exc
    return parse_capture_bytes(data, source=source)


def parse_capture_bytes(data: bytes, source: str = "<memory>") -> Capture:
    """Detect and parse pcap or pcapng bytes."""
    if not data:
        raise PcapError(f"{source}: file is empty")
    magic = data[:4]
    if magic in PCAP_MAGICS:
        return parse_pcap(data, source=source)
    if magic == SHB_BYTES:
        return parse_pcapng(data, source=source)
    raise PcapError(
        f"{source}: not a pcap or pcapng file (unknown magic number {magic.hex()})"
    )
