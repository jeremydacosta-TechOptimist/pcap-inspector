"""Tests for the HTML, text and Markdown report renderers."""

from __future__ import annotations

import unittest

from pcapkit.analysis import analyze
from pcapkit.demo import build_demo_capture
from pcapkit.models import Capture
from pcapkit.report import render_html, render_markdown, render_text


def demo_analysis():
    """Analyse the deterministic demo capture."""
    return analyze(build_demo_capture())


def empty_analysis():
    """Analyse an empty capture."""
    return analyze(
        Capture(
            source="empty.pcap",
            format="pcap",
            byte_order="little",
            version="2.4",
            snaplen=65535,
            linktype=1,
            packets=[],
        )
    )


class HtmlReportTests(unittest.TestCase):
    """The standalone HTML report."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.analysis = demo_analysis()
        cls.html = render_html(cls.analysis)

    def test_doctype_and_language(self) -> None:
        self.assertTrue(self.html.startswith("<!DOCTYPE html>"))
        self.assertIn('<html lang="en">', self.html)
        self.assertTrue(self.html.rstrip().endswith("</html>"))

    def test_required_sections_are_present(self) -> None:
        for heading in (
            "<h2>Capture summary</h2>",
            "<h2>Protocol distribution</h2>",
            "<h2>Top talkers</h2>",
            "<h2>Top conversations</h2>",
            "<h2>DNS activity</h2>",
            "<h2>Capture notes</h2>",
        ):
            self.assertIn(heading, self.html)

    def test_charts_are_inline_svg(self) -> None:
        self.assertGreaterEqual(self.html.count("<svg"), 2)
        self.assertIn('role="img"', self.html)
        self.assertIn("<title>", self.html)

    def test_no_external_assets_or_scripts(self) -> None:
        self.assertNotIn("<script", self.html)
        self.assertNotIn("http://", self.html)
        self.assertNotIn("https://", self.html)
        self.assertNotIn("<link", self.html)

    def test_contains_real_capture_values(self) -> None:
        self.assertIn("demo.pcap", self.html)
        self.assertIn("192.0.2.10", self.html)
        self.assertIn("TCP", self.html)
        self.assertIn("DNS", self.html)
        self.assertIn("27", self.html)

    def test_source_path_is_not_exposed(self) -> None:
        self.assertNotIn("github-repos", self.html)
        self.assertNotIn("C:\\", self.html)

    def test_dynamic_text_is_escaped(self) -> None:
        capture = build_demo_capture()
        capture.source = '<script>alert("x")</script>.pcap'
        rendered = render_html(analyze(capture))
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>alert", rendered)

    def test_top_limit_is_respected(self) -> None:
        rendered = render_html(self.analysis, top=3)
        self.assertIn("Showing the 3 busiest of 8 conversations.", rendered)
        self.assertIn("Showing 3 of 5 protocol labels.", rendered)

    def test_custom_title_is_used(self) -> None:
        rendered = render_html(self.analysis, title="Lab capture")
        self.assertIn("<title>Lab capture</title>", rendered)

    def test_empty_capture_renders_placeholders(self) -> None:
        rendered = render_html(empty_analysis())
        self.assertIn("No packets captured.", rendered)
        self.assertIn("No IP traffic captured.", rendered)
        self.assertIn("No IP conversations captured.", rendered)
        self.assertIn("empty.pcap", rendered)


class TextReportTests(unittest.TestCase):
    """Plain-text and Markdown reports."""

    def test_text_report_contains_summary_and_tables(self) -> None:
        report = render_text(demo_analysis())
        self.assertIn("Capture: demo.pcap", report)
        self.assertIn("Protocol distribution", report)
        self.assertIn("Top conversations", report)
        self.assertIn("Top talkers", report)
        self.assertIn("TCP", report)
        self.assertIn("192.0.2.10", report)
        self.assertIn("27", report)

    def test_text_report_for_empty_capture(self) -> None:
        report = render_text(empty_analysis())
        self.assertIn("Capture: empty.pcap", report)
        self.assertIn("no packets", report)
        self.assertIn("0", report)

    def test_markdown_report_contains_tables(self) -> None:
        report = render_markdown(demo_analysis())
        self.assertTrue(report.startswith("# Capture report: demo.pcap"))
        self.assertIn("| Protocol | Packets |", report)
        self.assertIn("## Top conversations", report)
        self.assertIn("## Top talkers", report)
        self.assertIn("| Address | Packets | Sent | Received | Total |", report)

    def test_markdown_limits_rows(self) -> None:
        report = render_markdown(demo_analysis(), top=2)
        self.assertIn("## DNS activity", report)
        dns_rows = [
            line
            for line in report.splitlines()
            if line.startswith("| ") and " -> " in line
        ]
        self.assertLessEqual(len(dns_rows), 2)


if __name__ == "__main__":
    unittest.main()
