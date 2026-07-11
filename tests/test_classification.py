import unittest

from dpi_engine.classification import (
    AppType,
    app_type_from_name,
    app_type_to_string,
    sni_to_app_type,
)


class ClassificationTests(unittest.TestCase):
    def test_known_domains_map_to_apps(self):
        cases = {
            "www.youtube.com": AppType.YOUTUBE,
            "www.google.com": AppType.GOOGLE,
            "www.facebook.com": AppType.FACEBOOK,
            "cdninstagram.com": AppType.INSTAGRAM,
            "github.com": AppType.GITHUB,
            "open.spotify.com": AppType.SPOTIFY,
            "www.tiktok.com": AppType.TIKTOK,
        }
        for domain, expected in cases.items():
            self.assertEqual(sni_to_app_type(domain), expected, domain)

    def test_matching_is_case_insensitive(self):
        self.assertEqual(sni_to_app_type("WWW.YouTube.COM"), AppType.YOUTUBE)

    def test_unknown_domain_is_generic_https(self):
        self.assertEqual(sni_to_app_type("some-random-host.example"), AppType.HTTPS)

    def test_empty_domain_is_unknown(self):
        self.assertEqual(sni_to_app_type(""), AppType.UNKNOWN)

    def test_app_type_to_string(self):
        self.assertEqual(app_type_to_string(AppType.TWITTER), "Twitter/X")

    def test_app_type_from_name_roundtrip(self):
        self.assertEqual(app_type_from_name("youtube"), AppType.YOUTUBE)
        self.assertEqual(app_type_from_name("Twitter/X"), AppType.TWITTER)
        self.assertIsNone(app_type_from_name("nope"))


if __name__ == "__main__":
    unittest.main()
