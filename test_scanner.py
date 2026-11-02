import asyncio
import csv
import io
import json
import socket
import unittest

from portscout.output import to_csv, to_json, to_table
from portscout.scanner import PortResult, parse_ports, scan, scan_port


class ParsePortsTests(unittest.TestCase):
    def test_single_list_and_range(self):
        self.assertEqual(parse_ports("80,22,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_deduplicates(self):
        self.assertEqual(parse_ports("80,80,79-80"), [79, 80])

    def test_rejects_bad_input(self):
        for bad in ["", "abc", "0", "65536", "10-5", "1-x"]:
            with self.subTest(spec=bad):
                with self.assertRaises(ValueError):
                    parse_ports(bad)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ScanTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def handler(reader, writer):
            writer.write(b"SSH-2.0-TestServer_1.0\r\n")
            await writer.drain()
            writer.close()

        self.server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.open_port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def test_open_port_with_banner(self):
        r = await scan_port("127.0.0.1", self.open_port, timeout=1.0)
        self.assertEqual(r.state, "open")
        self.assertEqual(r.banner, "SSH-2.0-TestServer_1.0")

    async def test_open_port_without_banner(self):
        r = await scan_port("127.0.0.1", self.open_port, grab_banner=False)
        self.assertEqual(r.state, "open")
        self.assertIsNone(r.banner)

    async def test_closed_port(self):
        r = await scan_port("127.0.0.1", free_port(), timeout=1.0)
        self.assertEqual(r.state, "closed")

    async def test_scan_sorted_and_mixed(self):
        closed = free_port()
        results = await scan(
            "127.0.0.1", sorted([self.open_port, closed]), concurrency=5, timeout=1.0
        )
        self.assertEqual([r.port for r in results], sorted([self.open_port, closed]))
        states = {r.port: r.state for r in results}
        self.assertEqual(states[self.open_port], "open")
        self.assertEqual(states[closed], "closed")

    async def test_unresolvable_host(self):
        with self.assertRaises(ValueError):
            await scan("no-such-host.invalid", [80], timeout=0.5)

    async def test_bad_concurrency(self):
        with self.assertRaises(ValueError):
            await scan("127.0.0.1", [80], concurrency=0)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.results = [
            PortResult("127.0.0.1", 22, "open", "ssh", "SSH-2.0-OpenSSH_9.6"),
            PortResult("127.0.0.1", 80, "open", "http", None),
        ]

    def test_json_round_trip(self):
        data = json.loads(to_json(self.results))
        self.assertEqual(data[0]["port"], 22)
        self.assertIsNone(data[1]["banner"])

    def test_csv_has_header_and_rows(self):
        rows = list(csv.DictReader(io.StringIO(to_csv(self.results))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["service"], "ssh")

    def test_table(self):
        table = to_table(self.results)
        self.assertIn("PORT", table)
        self.assertIn("SSH-2.0-OpenSSH_9.6", table)
        self.assertEqual(to_table([]), "No matching ports found.")


if __name__ == "__main__":
    unittest.main()
