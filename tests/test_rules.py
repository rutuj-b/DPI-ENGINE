import unittest

from dpi_engine.classification import AppType
from dpi_engine.rules import RuleManager


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.rules = RuleManager()

    def test_ip_block(self):
        self.rules.block_ip("192.168.1.50")
        reason = self.rules.should_block("192.168.1.50", 443, AppType.HTTPS, "")
        self.assertIsNotNone(reason)
        self.assertEqual(reason.kind, "ip")

    def test_app_block(self):
        self.rules.block_app(AppType.YOUTUBE)
        reason = self.rules.should_block("1.2.3.4", 443, AppType.YOUTUBE, "www.youtube.com")
        self.assertIsNotNone(reason)
        self.assertEqual(reason.kind, "app")

    def test_app_block_by_name(self):
        self.assertTrue(self.rules.block_app_name("YouTube"))
        self.assertFalse(self.rules.block_app_name("Nonexistent"))
        self.assertTrue(self.rules.is_app_blocked(AppType.YOUTUBE))

    def test_domain_substring_block(self):
        self.rules.block_domain("facebook")
        reason = self.rules.should_block("1.2.3.4", 443, AppType.FACEBOOK, "www.facebook.com")
        self.assertEqual(reason.kind, "domain")

    def test_domain_wildcard_block(self):
        self.rules.block_domain("*.tiktok.com")
        self.assertTrue(self.rules.is_domain_blocked("www.tiktok.com"))
        self.assertTrue(self.rules.is_domain_blocked("tiktok.com"))
        self.assertFalse(self.rules.is_domain_blocked("tiktok.evil.net"))

    def test_port_block(self):
        self.rules.block_port(53)
        reason = self.rules.should_block("1.2.3.4", 53, AppType.DNS, "")
        self.assertEqual(reason.kind, "port")

    def test_no_rule_allows(self):
        self.assertIsNone(self.rules.should_block("1.2.3.4", 443, AppType.HTTPS, "x.example"))

    def test_precedence_ip_over_app(self):
        self.rules.block_ip("9.9.9.9")
        self.rules.block_app(AppType.YOUTUBE)
        reason = self.rules.should_block("9.9.9.9", 443, AppType.YOUTUBE, "youtube.com")
        self.assertEqual(reason.kind, "ip")

    def test_stats(self):
        self.rules.block_ip("1.1.1.1")
        self.rules.block_app(AppType.NETFLIX)
        self.rules.block_domain("*.tiktok.com")
        self.rules.block_port(80)
        stats = self.rules.stats()
        self.assertEqual(stats.blocked_ips, 1)
        self.assertEqual(stats.blocked_apps, 1)
        self.assertEqual(stats.blocked_domains, 1)
        self.assertEqual(stats.blocked_ports, 1)


if __name__ == "__main__":
    unittest.main()
