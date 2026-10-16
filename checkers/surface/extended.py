"""
Extended surface checkers — 20 additional platforms for maximum coverage.
"""
from checkers.base import BaseChecker


class FacebookChecker(BaseChecker):
    ID, NAME = "facebook", "Facebook / Meta"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://www.facebook.com/help/delete_account"

    def check(self):
        import re as _re
        # Step 1: get the account recovery page to extract CSRF token
        rg = self._get(
            "https://www.facebook.com/login/identify/",
            params={"ctx": "recover"},
        )
        lsd = ""
        if rg:
            m = _re.search(r'"LSD"\s*,\s*\[\]\s*,\s*\{"token"\s*:\s*"([^"]+)"', rg.text)
            if m:
                lsd = m.group(1)

        # Step 2: submit the email to the account identify endpoint
        r = self._post(
            "https://www.facebook.com/login/identify/",
            data={"email": self.email, "lsd": lsd, "ctx": "recover",
                  "login_source": "6", "next": ""},
            headers={"Referer": "https://www.facebook.com/login/identify/?ctx=recover",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if ("is this your account" in text or "search results for" in text
                or "profile picture" in text or "enter the code" in text):
            return self.found("Facebook account found")
        if "couldn't find" in text or "we couldn" in text or "no account" in text or "try another" in text:
            return self.not_found("No Facebook account found")
        return self.unknown("Anti-bot protection active — Facebook deliberately hides account existence")


class GoogleChecker(BaseChecker):
    ID, NAME = "google", "Google Account"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://myaccount.google.com/delete-services-or-account"

    def check(self):
        r = self._post(
            "https://accounts.google.com/_/signin/sl/lookup",
            json={"identifier": self.email, "continue": "https://accounts.google.com/"},
            headers={"Content-Type": "application/json", "Google-Accounts-XSRF": "1"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text or "couldn't find" not in text and r.status_code == 200:
            if "couldn't find" in text or "no account" in text:
                return self.not_found("No Google account found")
            return self.unknown("Blocked (anti-bot — Google requires browser)")
        return self.unknown("Could not determine")


class NetflixChecker(BaseChecker):
    ID, NAME = "netflix", "Netflix"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://help.netflix.com/en/node/407"

    def check(self):
        r = self._post(
            "https://www.netflix.com/password",
            data={"email": self.email},
            headers={"Referer": "https://www.netflix.com/password"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "reset" in text or "check your email" in text or "sent" in text:
            return self.found("Netflix account found (reset email sent)")
        if "couldn" in text or "not found" in text or "no account" in text:
            return self.not_found("No Netflix account found")
        return self.unknown("Could not determine (anti-bot)")


class AirbnbChecker(BaseChecker):
    ID, NAME = "airbnb", "Airbnb"
    PRIVACY, CATEGORY = "api", "commerce"
    DELETE_URL = "https://www.airbnb.com/help/article/3151"

    def check(self):
        r = self._get(
            "https://www.airbnb.com/api/v2/users/check_email",
            params={"email": self.email},
            headers={"X-Airbnb-API-Key": "d306zoyjsyarp7ifhu67rjxn52tv0t20"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if data.get("email_available") is False:
                return self.found("Airbnb account found")
            if data.get("email_available") is True:
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class NotionChecker(BaseChecker):
    ID, NAME = "notion", "Notion"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://www.notion.so/help/delete-your-notion-account"

    def check(self):
        r = self._post(
            "https://www.notion.so/api/v3/findUser",
            json={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            val = data.get("value", {})
            if isinstance(val, dict) and val.get("value"):
                return self.found("Notion account found")
            if val is None or (isinstance(val, dict) and not val.get("value")):
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class SlackChecker(BaseChecker):
    ID, NAME = "slack", "Slack"
    PRIVACY, CATEGORY = "api", "services"
    DELETE_URL = "https://slack.com/help/articles/360003461254"

    def check(self):
        r = self._post(
            "https://slack.com/api/auth.findTeams",
            data={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if data.get("ok") and data.get("teams"):
                n = len(data["teams"])
                names = ", ".join(t.get("name", "?") for t in data["teams"][:3])
                return self.found(f"{n} workspace(s): {names}")
            if data.get("ok") is False:
                return self.not_found("No Slack workspaces found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class PlayStationChecker(BaseChecker):
    ID, NAME = "playstation", "PlayStation Network"
    PRIVACY, CATEGORY = "direct", "gaming"
    DELETE_URL = "https://www.playstation.com/en-us/support/account/"

    def check(self):
        r = self._post(
            "https://ca.account.sony.com/api/v1/ssocookie",
            json={"loginId": self.email, "password": "GhostTrace_Probe9z!"},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            err = data.get("error", {})
            code = err.get("code", "") if isinstance(err, dict) else str(err)
            # Wrong password = account exists; invalid user = no account
            if code in ("SEN-112002", "SEN-112001", "SEN-2300"):
                return self.found("PSN account found (wrong password)")
            if code in ("SEN-100027", "SEN-100030"):
                return self.not_found("Email not registered on PSN")
        except Exception:
            pass
        return self.unknown("Could not determine")


class UbisoftChecker(BaseChecker):
    ID, NAME = "ubisoft", "Ubisoft"
    PRIVACY, CATEGORY = "api", "gaming"
    DELETE_URL = "https://account.ubisoft.com/en-US/account-information"

    def check(self):
        r = self._post(
            "https://public-ubiservices.ubi.com/v3/profiles/sessions",
            json={"email": self.email, "password": "GhostTrace_Probe9z!"},
            headers={
                "Ubi-AppId": "86263886-327a-4328-ac69-527f0d20a237",
                "Content-Type": "application/json",
            },
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            ec = data.get("errorCode", 0)
            if ec in (1100, 1101, 1104, 1194, 1100):
                return self.found("Ubisoft account found")
            if ec == 1098:
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown("Could not determine")


class NintendoChecker(BaseChecker):
    ID, NAME = "nintendo", "Nintendo Account"
    PRIVACY, CATEGORY = "direct", "gaming"
    DELETE_URL = "https://accounts.nintendo.com/setting"

    def check(self):
        r = self._post(
            "https://accounts.nintendo.com/connect/1.0.0/token",
            data={
                "client_id": "71b963c1b7b6d119",
                "grant_type": "password",
                "username": self.email,
                "password": "GhostTrace_Probe9z!",
            },
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            err = str(data.get("error", "")).lower()
            desc = str(data.get("error_description", "")).lower()
            if "password" in err or "invalid_grant" in err:
                return self.found("Nintendo account found (wrong password)")
            if "not_found" in err or "user" in desc and "not" in desc:
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown("Could not determine")


class AppleChecker(BaseChecker):
    ID, NAME = "apple", "Apple ID"
    PRIVACY, CATEGORY = "api", "services"
    DELETE_URL = "https://privacy.apple.com/"

    def check(self):
        r = self._post(
            "https://appleid.apple.com/account/check/email",
            data={"email": self.email},
            headers={"Origin": "https://appleid.apple.com"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            errors = data.get("validationErrors", [])
            for e in errors:
                msg = str(e.get("message", "")).lower()
                if any(x in msg for x in ("already", "in use", "taken", "exists")):
                    return self.found("Apple ID found")
                if any(x in msg for x in ("valid", "format", "invalid")):
                    return self.unknown("Email format issue")
            if r.status_code == 200 and not errors:
                return self.not_found("Email available (no Apple ID)")
        except Exception:
            pass
        return self.unknown("Could not determine")


class YahooChecker(BaseChecker):
    ID, NAME = "yahoo", "Yahoo"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://login.yahoo.com/account/security"

    def check(self):
        r = self._post(
            "https://login.yahoo.com/config/login",
            data={"login": self.email, "passwd": "ghost_probe_!", ".persistent": "y", ".save": ""},
            headers={"Referer": "https://login.yahoo.com/"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "challenge" in text or "password" in text or "verify" in text:
            return self.found("Yahoo account found")
        if "invalid id" in text or "we couldn" in text or "don't recognize" in text:
            return self.not_found("No Yahoo account found")
        return self.unknown("Could not determine (anti-bot)")


class BookingChecker(BaseChecker):
    ID, NAME = "booking", "Booking.com"
    PRIVACY, CATEGORY = "direct", "commerce"
    DELETE_URL = "https://account.booking.com/settings"

    def check(self):
        r = self._post(
            "https://account.booking.com/oauth2/authorize",
            data={"username": self.email, "action": "sign_in"},
            headers={"Referer": "https://account.booking.com/sign-in"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text or "enter your password" in text:
            return self.found("Booking.com account found")
        if "create" in text or "sign up" in text or "not found" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine")


class SubstackChecker(BaseChecker):
    ID, NAME = "substack", "Substack"
    PRIVACY, CATEGORY = "api", "media"
    DELETE_URL = "https://substack.com/settings"

    def check(self):
        r = self._post(
            "https://substack.com/api/v1/email/exists",
            json={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if data.get("exists") is True:
                return self.found("Substack account found")
            if data.get("exists") is False:
                return self.not_found("Email not registered")
        except Exception:
            pass
        # Fallback: probe login
        r2 = self._post(
            "https://substack.com/api/v1/login",
            json={"email": self.email, "password": "GhostTrace_Probe9z!"},
        )
        if r2:
            text = r2.text.lower()
            if "password" in text or "incorrect" in text:
                return self.found("Substack account found (wrong password)")
            if "no account" in text or "not registered" in text:
                return self.not_found("Email not registered")
        return self.unknown("Could not determine")


class KickstarterChecker(BaseChecker):
    ID, NAME = "kickstarter", "Kickstarter"
    PRIVACY, CATEGORY = "direct", "commerce"
    DELETE_URL = "https://www.kickstarter.com/settings/delete_account"

    def check(self):
        r = self._get(
            "https://www.kickstarter.com/signup/email_check",
            params={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if data.get("taken") is True:
                return self.found("Kickstarter account found")
            if data.get("taken") is False:
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class FiverrChecker(BaseChecker):
    ID, NAME = "fiverr", "Fiverr"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://www.fiverr.com/settings/security"

    def check(self):
        r = self._post(
            "https://www.fiverr.com/users/sign_in",
            json={"user": {"email": self.email, "password": "GhostTrace_Probe9z!"}},
            headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("invalid" in text or "incorrect" in text or "wrong" in text):
            return self.found("Fiverr account found (wrong password)")
        if "email" in text and ("not found" in text or "no account" in text):
            return self.not_found("No account found")
        return self.unknown("Could not determine (anti-bot)")


class DribbbleChecker(BaseChecker):
    ID, NAME = "dribbble", "Dribbble"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://dribbble.com/account/delete_profile"

    def check(self):
        r = self._get(
            "https://dribbble.com/users/exists",
            params={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if data.get("exists") is True:
                return self.found("Dribbble account found")
            if data.get("exists") is False:
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class ProtonMailChecker(BaseChecker):
    ID, NAME = "protonmail", "Proton Mail"
    PRIVACY, CATEGORY = "api", "services"
    DELETE_URL = "https://account.proton.me/settings#deleteAccount"

    def check(self):
        local = self.email.split("@")[0]
        r = self._get(
            "https://account.proton.me/api/core/v4/users/available",
            params={"Name": local},
            headers={"X-Pm-Appversion": "web-account@5.0.0.0"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            code = data.get("Code", -1)
            if code == 12011:
                return self.found("Proton Mail username taken (account exists)")
            if code == 1000:
                return self.not_found("Proton Mail username available")
        except Exception:
            pass
        return self.unknown("Could not determine")


class TelegramChecker(BaseChecker):
    ID, NAME = "telegram", "Telegram"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://my.telegram.org/auth"

    def check(self):
        # Telegram is phone-number based; check via web auth initiation
        r = self._post(
            "https://my.telegram.org/auth/send_password",
            data={"phone": self.email},
        )
        if not r:
            # Try login with email as username hint
            r2 = self._post(
                "https://my.telegram.org/auth/login",
                data={"login_string": self.email, "password": ""},
            )
            if r2 and "password" in r2.text.lower():
                return self.found("Telegram account found")
            return self.error("Connection failed")
        text = r.text.lower()
        if "account" in text or "password" in text:
            return self.found("Telegram account found")
        return self.unknown("Telegram is phone-based — email match inconclusive")


class ThreadsChecker(BaseChecker):
    ID, NAME = "threads", "Threads (Meta)"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://www.threads.net/settings/account"

    def check(self):
        # Threads shares the Instagram/Meta account — check via Instagram password reset
        r = self._post(
            "https://www.instagram.com/accounts/account_recovery_send_ajax/",
            data={"email_or_username": self.email, "recaptcha_challenge_field": ""},
            headers={"X-Requested-With": "XMLHttpRequest", "Referer": "https://www.instagram.com/accounts/password/reset/"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if data.get("status") == "ok":
                return self.found("Threads/Instagram account found (password reset email available)")
        except Exception:
            pass
        return self.unknown("Could not determine (anti-bot)")


class BlueSkyChecker(BaseChecker):
    ID, NAME = "bluesky", "Bluesky"
    PRIVACY, CATEGORY = "api", "social"
    DELETE_URL = "https://bsky.app/settings"

    def check(self):
        r = self._post(
            "https://bsky.social/xrpc/com.atproto.server.createSession",
            json={"identifier": self.email, "password": "GhostTrace_Probe9z!"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            err = str(data.get("error", "")).lower()
            msg = str(data.get("message", "")).lower()
            if "invalid" in err and "password" in msg:
                return self.found("Bluesky account found (wrong password)")
            if "account" in err and "not" in msg:
                return self.not_found("Email not registered on Bluesky")
            if "invalid" in err and "identifier" in msg:
                return self.not_found("Email not registered on Bluesky")
        except Exception:
            pass
        return self.unknown("Could not determine")


class MastodonChecker(BaseChecker):
    ID, NAME = "mastodon", "Mastodon (mastodon.social)"
    PRIVACY, CATEGORY = "api", "social"
    DELETE_URL = "https://mastodon.social/settings/profile"

    def check(self):
        r = self._post(
            "https://mastodon.social/auth/sign_in",
            data={"user[email]": self.email, "user[password]": "GhostTrace_Probe9z!"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "invalid email or password" in text:
            return self.found("Mastodon account found (wrong password)")
        if "sign up" in text or r.status_code == 200 and "password" not in text:
            return self.unknown("Could not determine (anti-bot)")
        return self.unknown("Could not determine")


class PolyworkChecker(BaseChecker):
    ID, NAME = "polywork", "Polywork"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://www.polywork.com/settings"

    def check(self):
        r = self._post(
            "https://www.polywork.com/users/sign_in.json",
            json={"user": {"email": self.email, "password": "GhostTrace_Probe9z!"}},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text or "incorrect" in text or "invalid" in text:
            return self.found("Polywork account found (wrong password)")
        if "not found" in text or "no account" in text:
            return self.not_found("No Polywork account found")
        return self.unknown("Could not determine (anti-bot)")


class UberChecker(BaseChecker):
    ID, NAME = "uber", "Uber"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://help.uber.com/riders/article/delete-your-uber-account"

    def check(self):
        r = self._post(
            "https://auth.uber.com/v2/oauth/token",
            data={
                "client_id": "65e9605d-dbf4-4d63-aa46-dc7e012f37e4",
                "grant_type": "password",
                "username": self.email,
                "password": "GhostTrace_Probe9z!",
                "scope": "profile",
            },
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            err = str(data.get("error", "")).lower()
            if "invalid_credentials" in err or "password" in err:
                return self.found("Uber account found (wrong password)")
            if "not_found" in err or "no account" in err:
                return self.not_found("Email not registered on Uber")
        except Exception:
            pass
        return self.unknown("Could not determine")


class WhatsAppChecker(BaseChecker):
    ID, NAME = "whatsapp", "WhatsApp"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://faq.whatsapp.com/1068668370783756"

    def check(self):
        # WhatsApp is phone-based; email lookup is not supported directly
        return self.unknown(
            "WhatsApp is phone-number based — use Phone OSINT tab to check WhatsApp registration"
        )


class BeehiivChecker(BaseChecker):
    ID, NAME = "beehiiv", "Beehiiv"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://app.beehiiv.com/settings"

    def check(self):
        r = self._post(
            "https://app.beehiiv.com/api/v2/auth/sign_in",
            json={"email": self.email, "password": "GhostTrace_Probe9z!"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if "password" in str(data).lower() or "invalid" in str(data).lower():
                return self.found("Beehiiv account found (wrong password)")
            if "not found" in str(data).lower():
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown("Could not determine")


class EAChecker(BaseChecker):
    ID, NAME = "ea", "EA / Origin"
    PRIVACY, CATEGORY = "direct", "gaming"
    DELETE_URL = "https://myaccount.ea.com/cp-ui/deletemyaccount/index"

    def check(self):
        r = self._post(
            "https://signin.ea.com/p/web2/login",
            data={
                "email": self.email,
                "password": "GhostTrace_Probe9z!",
                "_eventId": "submit",
                "cid": "12",
                "showAgeUp": "1",
                "thirdPartyCoppaStatus": "",
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://signin.ea.com/p/web2/login",
            },
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("incorrect" in text or "wrong" in text or "invalid" in text):
            return self.found("EA account found (wrong password)")
        if "email" in text and ("not found" in text or "doesn't exist" in text):
            return self.not_found("No EA account found")
        return self.unknown("Could not determine (anti-bot)")
