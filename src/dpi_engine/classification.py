"""Application classification from domain names (SNI / Host / DNS)."""

from __future__ import annotations

import enum


class AppType(enum.Enum):
    """A traffic classification label."""

    UNKNOWN = "Unknown"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "Google"
    FACEBOOK = "Facebook"
    YOUTUBE = "YouTube"
    TWITTER = "Twitter/X"
    INSTAGRAM = "Instagram"
    NETFLIX = "Netflix"
    AMAZON = "Amazon"
    MICROSOFT = "Microsoft"
    APPLE = "Apple"
    WHATSAPP = "WhatsApp"
    TELEGRAM = "Telegram"
    TIKTOK = "TikTok"
    SPOTIFY = "Spotify"
    ZOOM = "Zoom"
    DISCORD = "Discord"
    GITHUB = "GitHub"
    CLOUDFLARE = "Cloudflare"


def app_type_to_string(app: AppType) -> str:
    """Return the human-readable label for an application type."""
    return app.value


# Ordered signature table: the first application whose any keyword appears in
# the (lower-cased) domain wins. Order matters — e.g. Google is checked before
# YouTube-specific hosts, matching the historical precedence.
_SIGNATURES: list[tuple[AppType, tuple[str, ...]]] = [
    (AppType.GOOGLE, ("google", "gstatic", "googleapis", "ggpht", "gvt1")),
    (AppType.YOUTUBE, ("youtube", "ytimg", "youtu.be", "yt3.ggpht")),
    (AppType.FACEBOOK, ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")),
    (AppType.INSTAGRAM, ("instagram", "cdninstagram")),
    (AppType.WHATSAPP, ("whatsapp", "wa.me")),
    (AppType.TWITTER, ("twitter", "twimg", "x.com", "t.co")),
    (AppType.NETFLIX, ("netflix", "nflxvideo", "nflximg")),
    (AppType.AMAZON, ("amazon", "amazonaws", "cloudfront", "aws")),
    (
        AppType.MICROSOFT,
        ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"),
    ),
    (AppType.APPLE, ("apple", "icloud", "mzstatic", "itunes")),
    (AppType.TELEGRAM, ("telegram", "t.me")),
    (AppType.TIKTOK, ("tiktok", "tiktokcdn", "musical.ly", "bytedance")),
    (AppType.SPOTIFY, ("spotify", "scdn.co")),
    (AppType.ZOOM, ("zoom",)),
    (AppType.DISCORD, ("discord", "discordapp")),
    (AppType.GITHUB, ("github", "githubusercontent")),
    (AppType.CLOUDFLARE, ("cloudflare", "cf-")),
]


def sni_to_app_type(domain: str) -> AppType:
    """Map a domain name to an application type via keyword signatures.

    A recognised but unlisted domain is reported as generic HTTPS; an empty
    domain is UNKNOWN.
    """
    if not domain:
        return AppType.UNKNOWN

    lowered = domain.lower()
    for app, keywords in _SIGNATURES:
        if any(keyword in lowered for keyword in keywords):
            return app

    # A domain was present but did not match a known application.
    return AppType.HTTPS


def app_type_from_name(name: str) -> AppType | None:
    """Resolve a user-supplied application name (e.g. ``"YouTube"``).

    Matching is case-insensitive against the display labels.
    """
    target = name.strip().lower()
    for app in AppType:
        if app.value.lower() == target:
            return app
    return None
