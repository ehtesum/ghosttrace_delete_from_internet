"""
Plugin registry — add a new checker class here to include it in scans.
Surface: run against the open web.
Deep:    run against breach DBs, paste sites, cert logs, infostealers.
"""

from checkers.surface.identity import GravatarChecker
from checkers.surface.breaches import HIBPChecker, EmailRepChecker
from checkers.surface.developer import GitHubChecker, GitLabChecker, BitbucketChecker
from checkers.surface.social import (
    TwitterChecker, InstagramChecker, RedditChecker, PinterestChecker,
    TumblrChecker, LinkedInChecker, SnapchatChecker, TikTokChecker, MicrosoftChecker,
)
from checkers.surface.media import (
    SpotifyChecker, SoundCloudChecker, TwitchChecker, VimeoChecker, DuolingoChecker,
)
from checkers.surface.services import (
    AdobeChecker, DropboxChecker, ZoomChecker, MediumChecker,
    WordPressChecker, PatreonChecker, DiscordChecker,
)
from checkers.surface.commerce import EbayChecker, PayPalChecker, EtsyChecker
from checkers.surface.gaming import SteamChecker, RobloxChecker, EpicGamesChecker, BattleNetChecker

# Extended checkers — 20 additional platforms
from checkers.surface.extended import (
    FacebookChecker, GoogleChecker, NetflixChecker,
    AirbnbChecker, NotionChecker, SlackChecker,
    PlayStationChecker, UbisoftChecker, NintendoChecker,
    AppleChecker, YahooChecker, BookingChecker,
    SubstackChecker, KickstarterChecker, FiverrChecker,
    DribbbleChecker, ProtonMailChecker, TelegramChecker, EAChecker,
    ThreadsChecker, BlueSkyChecker, MastodonChecker,
    PolyworkChecker, UberChecker, BeehiivChecker, WhatsAppChecker,
)
from checkers.surface.extra import (
    CanvaChecker, FigmaChecker, UdemyChecker, CourseraChecker,
    CoinbaseChecker, BinanceChecker, BandcampChecker, DeezerChecker,
    KofiChecker, GumroadChecker, DevToChecker, AcademiaChecker,
    LastFmChecker, StackOverflowChecker, HashNodeChecker,
)

from checkers.deep.certificates import CrtShChecker
from checkers.deep.infostealers import HudsonRockChecker, LeakCheckChecker, BreachDirectoryChecker
from checkers.deep.exposure import GitHubCodeChecker, PasteDorkChecker
from checkers.deep.brokers import DataBrokerChecker
from checkers.deep.onion import AhmiaChecker, IntelXChecker, SnusbaseChecker, DehashedChecker, OnionEmailChecker

# ── ordered lists used by the scanner ──────────────────────────────────────

SURFACE_CHECKERS = [
    # Breaches first — highest signal
    HIBPChecker, EmailRepChecker,
    # Identity
    GravatarChecker,
    # Developer
    GitHubChecker, GitLabChecker, BitbucketChecker,
    # Social
    TwitterChecker, InstagramChecker, FacebookChecker, RedditChecker,
    PinterestChecker, TumblrChecker, LinkedInChecker, SnapchatChecker,
    TikTokChecker, TelegramChecker,
    # Media / entertainment
    SpotifyChecker, SoundCloudChecker, TwitchChecker, VimeoChecker,
    DuolingoChecker, SubstackChecker,
    # Services
    AdobeChecker, DropboxChecker, ZoomChecker, MediumChecker,
    WordPressChecker, PatreonChecker, DiscordChecker, MicrosoftChecker,
    AppleChecker, YahooChecker, GoogleChecker, SlackChecker,
    NotionChecker, ProtonMailChecker, FiverrChecker, DribbbleChecker,
    # Commerce
    EbayChecker, PayPalChecker, EtsyChecker, AirbnbChecker,
    BookingChecker, KickstarterChecker,
    # Gaming
    SteamChecker, RobloxChecker, EpicGamesChecker, BattleNetChecker,
    PlayStationChecker, NintendoChecker, UbisoftChecker, EAChecker, NetflixChecker,
    # New social / services
    ThreadsChecker, BlueSkyChecker, MastodonChecker,
    PolyworkChecker, UberChecker, BeehiivChecker, WhatsAppChecker,
    # Extra: design, education, finance, music, dev community
    CanvaChecker, FigmaChecker, UdemyChecker, CourseraChecker,
    CoinbaseChecker, BinanceChecker, BandcampChecker, DeezerChecker,
    KofiChecker, GumroadChecker, DevToChecker, AcademiaChecker,
    LastFmChecker, StackOverflowChecker, HashNodeChecker,
]

DEEP_CHECKERS = [
    # Breach / infostealer databases
    HudsonRockChecker, LeakCheckChecker, BreachDirectoryChecker,
    # Extended breach DBs
    SnusbaseChecker, DehashedChecker, IntelXChecker,
    # Infrastructure exposure
    CrtShChecker,
    # Public web exposure
    GitHubCodeChecker, PasteDorkChecker,
    # Dark web index
    AhmiaChecker, OnionEmailChecker,
    # Data broker landscape
    DataBrokerChecker,
]
