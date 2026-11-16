"""End-to-end tests for the pcapkit command line interface.

Every test runs ``python -m pcapkit`` in a subprocess with an absolute
``PYTHONPATH`` pointing at ``src`` so both the pytest and unittest runners, on
any Python version, exercise the real entry point.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


def run_cli(
    *arguments: str, cwd: str | Path | None = None, timeout: int = 120
) -> subprocess.CompletedProcess[str]:
    """Run ``python -m pcapkit`` in a subprocess."""
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = (
        str(SRC_DIR) + (os.pathsep + existing if existing else "")
    )
    return subprocess.run(
        [sys.executable, "-m", "pcapkit", *arguments],
        cwd=str(cwd) if cwd is not None else str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=environment,
        timeout=timeout,
        check=False,
    )


class CliUsageTests(unittest.TestCase):
    """Help, version and usage errors."""

    def test_help_lists_subcommands(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        for command in ("demo", "inspect", "flows", "report"):
            self.assertIn(command, result.stdout)

    def test_version(self) -> None:
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("pcapkit 1.0.0", result.stdout)

    def test_unknown_command_exits_with_usage_error(self) -> None:
        result = run_cli("bogus")
        self.assertEqual(result.returncode, 2)
        self.assertIn("COMMAND", result.stderr)

    def test_missing_file_argument_exits_with_usage_error(self) -> None:
        result = run_cli("inspect")
        self.assertEqual(result.returncode, 2)

    def test_missing_capture_exits_with_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_cli("inspect", "does-not-exist.pcap", cwd=directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn("pcapkit: error:", result.stderr)

    def test_invalid_capture_exits_with_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            junk = Path(directory) / "junk.bin"
            junk.write_bytes(b"not a capture file at all")
            result = run_cli("inspect", "junk.bin", cwd=directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not a pcap or pcapng file", result.stderr)


class CliWorkflowTests(unittest.TestCase):
    """The demo -> inspect -> flows -> report workflow."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.directory = Path(self._directory.name)
        demo = run_cli("demo", cwd=self.directory)
        self.assertEqual(demo.returncode, 0, demo.stderr)
        self.assertTrue((self.directory / "demo.pcap").exists())

    def tearDown(self) -> None:
        self._directory.cleanup()

    def test_demo_refuses_to_overwrite_without_force(self) -> None:
        result = run_cli("demo", cwd=self.directory)
        self.assertEqual(result.returncode, 1)
        self.assertIn("already exists", result.stderr)
        forced = run_cli("demo", "--force", cwd=self.directory)
        self.assertEqual(forced.returncode, 0)

    def test_inspect_text_output(self) -> None:
        result = run_cli("inspect", "demo.pcap", cwd=self.directory)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Source: demo.pcap", result.stdout)
        self.assertIn("DNS query www.example.com A", result.stdout)
        self.assertIn("TCP 192.0.2.10:49876 -> 198.51.100.80:80 [SYN]", result.stdout)
        self.assertIn("Protocols: TCP 13, DNS 8", result.stdout)
        self.assertIn("Top talkers:", result.stdout)

    def test_inspect_limit_truncates_the_listing(self) -> None:
        result = run_cli("inspect", "demo.pcap", "--limit", "3", cwd=self.directory)
        self.assertEqual(result.returncode, 0)
        self.assertIn("... 24 more packet(s)", result.stdout)
        self.assertLessEqual(result.stdout.count("2026-01-15T09:00:00"), 5)

    def test_inspect_json(self) -> None:
        result = run_cli("inspect", "demo.pcap", "--json", cwd=self.directory)
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["generator"], "pcapkit 1.0.0")
        self.assertEqual(payload["capture"]["format"], "pcap")
        self.assertEqual(payload["summary"]["packets"], 27)
        self.assertEqual(len(payload["packets"]), 27)
        self.assertEqual(payload["packets"][3]["protocol"], "DNS")
        self.assertEqual(payload["packets"][6]["tcp"]["flags"], ["ACK"])

    def test_flows_text_output(self) -> None:
        result = run_cli("flows", "demo.pcap", cwd=self.directory)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Top conversations", result.stdout)
        self.assertIn("192.0.2.10:49876", result.stdout)
        self.assertIn("flows: 8", result.stdout)
        self.assertIn("Top talkers", result.stdout)

    def test_flows_json(self) -> None:
        result = run_cli("flows", "demo.pcap", "--json", cwd=self.directory)
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(len(payload["flows"]), 8)
        self.assertEqual(payload["summary"]["flow_count"], 8)
        self.assertEqual(payload["flows"][0]["protocol"], "TCP")
        self.assertEqual(len(payload["protocols"]), 5)
        self.assertTrue(payload["talkers"])

    def test_report_html(self) -> None:
        result = run_cli("report", "demo.pcap", "-o", "report.html", cwd=self.directory)
        self.assertEqual(result.returncode, 0)
        html = (self.directory / "report.html").read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<svg", html)
        self.assertIn("Protocol distribution", html)
        self.assertIn("Top talkers", html)
        self.assertIn("Top conversations", html)
        self.assertNotIn("<script", html)
        self.assertIn("Wrote HTML report to report.html", result.stdout)

    def test_report_text_and_markdown_formats(self) -> None:
        text = run_cli("report", "demo.pcap", "--format", "text", "-o", "report.txt", cwd=self.directory)
        self.assertEqual(text.returncode, 0)
        self.assertIn("Capture: demo.pcap", (self.directory / "report.txt").read_text(encoding="utf-8"))
        markdown = run_cli(
            "report", "demo.pcap", "--format", "markdown", "-o", "report.md", cwd=self.directory
        )
        self.assertEqual(markdown.returncode, 0)
        self.assertIn(
            "# Capture report: demo.pcap",
            (self.directory / "report.md").read_text(encoding="utf-8"),
        )

    def test_default_output_names_follow_the_format(self) -> None:
        result = run_cli("report", "demo.pcap", cwd=self.directory)
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.directory / "report.html").exists())


if __name__ == "__main__":
    unittest.main()
