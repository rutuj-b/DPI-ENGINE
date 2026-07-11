import os
import tempfile
import unittest

from dpi_engine.capture_gen import generate
from dpi_engine.classification import AppType
from dpi_engine.engine import DPIEngine, EngineConfig
from dpi_engine.pcap import PcapReader
from dpi_engine.rules import RuleManager


class EngineEndToEndTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.input = os.path.join(self._dir.name, "in.pcap")
        self.output = os.path.join(self._dir.name, "out.pcap")
        generate(self.input, seed=42)

    def _count(self, path: str) -> int:
        with PcapReader(path) as reader:
            return sum(1 for _ in reader)

    def test_no_rules_forwards_everything(self):
        engine = DPIEngine(config=EngineConfig(2, 2))
        result = engine.process(self.input, self.output)
        stats = result.stats
        self.assertGreater(stats["total_packets"], 0)
        self.assertEqual(stats["dropped"], 0)
        self.assertEqual(stats["forwarded"], stats["total_packets"])
        self.assertEqual(self._count(self.output), stats["forwarded"])

    def test_classification_detects_known_domains(self):
        engine = DPIEngine(config=EngineConfig(2, 2))
        result = engine.process(self.input, self.output)
        domains = result.stats["detected_domains"]
        self.assertIn("www.youtube.com", domains)
        self.assertEqual(domains["www.youtube.com"], AppType.YOUTUBE)
        self.assertIn("github.com", domains)

    def test_block_app_drops_packets(self):
        rules = RuleManager()
        rules.block_app(AppType.YOUTUBE)
        engine = DPIEngine(config=EngineConfig(2, 2), rules=rules)
        result = engine.process(self.input, self.output)
        self.assertGreater(result.stats["dropped"], 0)
        self.assertEqual(
            self._count(self.output), result.stats["forwarded"]
        )

    def test_block_ip_drops_that_source(self):
        rules = RuleManager()
        rules.block_ip("192.168.1.50")  # the synthetic "blocked" source
        engine = DPIEngine(config=EngineConfig(2, 2), rules=rules)
        result = engine.process(self.input, self.output)
        self.assertEqual(result.stats["dropped"], 5)

    def test_dispatch_and_processed_totals_match(self):
        engine = DPIEngine(config=EngineConfig(2, 2))
        result = engine.process(self.input, self.output)
        total = result.stats["total_packets"]
        self.assertEqual(sum(result.lb_dispatched), total)
        self.assertEqual(sum(result.fp_processed), total)

    def test_single_worker_pipeline(self):
        engine = DPIEngine(config=EngineConfig(1, 1))
        result = engine.process(self.input, self.output)
        self.assertGreater(result.stats["total_packets"], 0)
        self.assertEqual(result.stats["dropped"], 0)


if __name__ == "__main__":
    unittest.main()
