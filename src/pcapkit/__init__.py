"""pcapkit - a zero-dependency packet capture analyzer for pcap and pcapng.

Public API summary::

    from pcapkit import read_capture, analyze, render_html

    capture = read_capture("capture.pcap")
    analysis = analyze(capture)
    print(analysis.summary.packets)

The package has no third-party runtime dependencies; everything is implemented
with the Python standard library.
"""

from .analysis import CaptureAnalysis, analyze
from .decode import decode_capture, decode_packet, describe_packet
from .errors import DnsDecodeError, PcapError
from .models import Capture, CapturedPacket, DecodedPacket
from .pcap import read_pcap, write_pcap
from .pcapng import read_pcapng
from .reader import read_capture
from .report import render_html, render_markdown, render_text
from .version import __version__

__all__ = [
    "Capture",
    "CaptureAnalysis",
    "CapturedPacket",
    "DecodedPacket",
    "DnsDecodeError",
    "PcapError",
    "__version__",
    "analyze",
    "decode_capture",
    "decode_packet",
    "describe_packet",
    "read_capture",
    "read_pcap",
    "read_pcapng",
    "render_html",
    "render_markdown",
    "render_text",
    "write_pcap",
]
