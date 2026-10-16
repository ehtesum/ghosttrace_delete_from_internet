from checkers.base import BaseChecker


class TwitterChecker(BaseChecker):
    ID, NAME = "twitter", "Twitter / X"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://help.twitter.com/en/managing-your-account/how-to-deactivate-twitter-account"

    def check(self):
        # Try password reset flow — X sends reset email only to registered accounts
        r = self._post(
            "https://twitter.com/account/begin_password_reset.json",
            data={"account_identifier": self.email},
            headers={"Referer": "https://twitter.com/account/begin_password_reset"},
        )
        if r:
            text = r.text.lower()
            if "we sent" in text or "check your email" in text or "password reset" in text:
                return self.found("Account found (password reset email sent)")
            if "no account" in text or "couldn" in text or "not found" in text:
                return self.not_found("No account found")
            try:
                taken = not r.json().get("valid", True)
                return self.found("Email registered") if taken else self.not_found("Email available")
            except Exception:
                pass

        r2 = self._get(
            "https://api.twitter.com/i/users/email_available.json",
            params={"email": self.email},
            headers={"Referer": "https://twitter.com/account/begin_password_reset"},
        )
        if r2 and r2.status_code == 200:
            try:
                taken = not r2.json().get("valid", True)
                return self.found("Email registered") if taken else self.not_found("Email available")
            except Exception:
                pass
        if not r:
            return self.error("Connection failed")
        return self.unknown("Anti-bot protection active — X deliberately hides account existence")


class InstagramChecker(BaseChecker):
    ID, NAME = "instagram", "Instagram"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://help.instagram.com/370452623149242"

    def check(self):
        reset_url = "https://www.instagram.com/accounts/password/reset/"
        pre = self._get(reset_url, headers={"Referer": "https://www.instagram.com/"})
        csrf_token = ""
        if pre:
            csrf_token = pre.cookies.get("csrftoken", "")
            if not csrf_token:
                import re as _re
                m = _re.search(r'"csrf_token":"([^"]+)"', pre.text)
                if m:
                    csrf_token = m.group(1)

        r = self._post(
            "https://www.instagram.com/accounts/account_recovery_send_ajax/",
            data={"email": self.email},
            headers={
                "Referer": reset_url,
                "Origin": "https://www.instagram.com",
                "X-Requested-With": "XMLHttpRequest",
                "X-CSRFToken": csrf_token,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 429:
            return self.unknown("Anti-bot protection active")
        if r.status_code == 200:
            try:
                d = r.json()
                status = str(d.get("status", "")).lower()
                message = str(d.get("message", "")).lower()
                if status == "ok" or ("email" in message and "sent" in message):
                    return self.found("Account found")
                if status == "fail" and ("doesn't exist" in message or "no users found" in message or "not found" in message):
                    return self.not_found("No account found")
            except Exception:
                pass
        if r.status_code in (400, 404):
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class RedditChecker(BaseChecker):
    ID, NAME = "reddit", "Reddit"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://www.reddit.com/settings/"

    def check(self):
        self._get("https://www.reddit.com/register", headers={"Referer": "https://www.reddit.com/"})
        r = self._post(
            "https://www.reddit.com/api/register",
            data={"email": self.email, "op": "reg", "user": "g__test__", "passwd": "", "passwd2": ""},
            headers={
                "Origin": "https://www.reddit.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://www.reddit.com/register/",
            },
        )
        if not r:
            return self.error("Connection failed")
        try:
            errs = str(r.json().get("json", {}).get("errors", [])).lower()
            if "taken" in errs or "already" in errs:
                return self.found("Email already registered")
            if "captcha" in errs or "tricky" in errs:
                return self.unknown("Anti-bot protection active")
        except Exception:
            pass
        text = r.text.lower()
        if "captcha" in text or "tricky one" in text:
            return self.unknown("Anti-bot protection active")
        return self.unknown("Could not determine")


class PinterestChecker(BaseChecker):
    ID, NAME = "pinterest", "Pinterest"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://help.pinterest.com/en/article/deactivate-or-close-your-account"

    def check(self):
        import json as _json
        self._get("https://www.pinterest.com/", headers={"Referer": "https://www.pinterest.com/"})
        r = self._get(
            "https://www.pinterest.com/resource/EmailExistsResource/get/",
            params={"source_url": "/", "data": _json.dumps({"options": {"email": self.email}})},
            headers={
                "Referer": "https://www.pinterest.com/",
                "Origin": "https://www.pinterest.com",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/javascript, */*; q=0.01",
            },
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 403:
            return self.unknown("Anti-bot protection active")
        try:
            exists = r.json().get("resource_response", {}).get("data", False)
            return self.found("Email registered") if exists else self.not_found("Email not registered")
        except Exception:
            return self.unknown(f"HTTP {r.status_code}")


class TumblrChecker(BaseChecker):
    ID, NAME = "tumblr", "Tumblr"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://tumblr.com/account/delete"

    def check(self):
        r = self._post("https://www.tumblr.com/api/v2/user/login",
                       headers={"Content-Type": "application/json"},
                       json={"email": self.email, "password": "ghost_probe_x9z"})
        if not r:
            return self.error("Connection failed")
        try:
            msg = str(r.json().get("meta", {}).get("msg", "")).lower()
            if "password" in msg or "incorrect" in msg:
                return self.found("Account found (wrong password)")
            if "not found" in msg or "no account" in msg:
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class LinkedInChecker(BaseChecker):
    ID, NAME = "linkedin", "LinkedIn"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://www.linkedin.com/help/linkedin/answer/a1341988"

    def check(self):
        r = self._post(
            "https://www.linkedin.com/checkpoint/lg/login-submit",
            data={"session_key": self.email, "session_password": "gh0st_probe_"},
            headers={"Referer": "https://www.linkedin.com/login"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("incorrect" in text or "wrong" in text):
            return self.found("Account found (wrong password)")
        if "email" in text and "doesn" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine (anti-bot)")


class SnapchatChecker(BaseChecker):
    ID, NAME = "snapchat", "Snapchat"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://accounts.snapchat.com/accounts/delete_account"

    def check(self):
        r = self._post(
            "https://accounts.snapchat.com/accounts/login",
            json={"email": self.email, "password": "GhostProbe9z!"},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("invalid" in text or "incorrect" in text or "wrong" in text):
            return self.found("Account exists (wrong password)")
        if "no account" in text or "not found" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine (anti-bot)")


class TikTokChecker(BaseChecker):
    ID, NAME = "tiktok", "TikTok"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://support.tiktok.com/en/account-and-privacy/deleting-an-account"

    def check(self):
        r = self._post(
            "https://www.tiktok.com/api/v1/api/user/password/reset/",
            json={"email": self.email},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            code = r.json().get("code", -1)
            # 0 = email sent (account exists), 10101/10102 = not found
            if code == 0:
                return self.found("Account found (reset email sent)")
            if str(code).startswith("101"):
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown("Could not determine (anti-bot)")


class MicrosoftChecker(BaseChecker):
    ID, NAME = "microsoft", "Microsoft"
    PRIVACY, CATEGORY = "api", "services"
    DELETE_URL = "https://account.microsoft.com/account/privacy"

    def check(self):
        r = self._post(
            "https://login.live.com/GetCredentialType.srf",
            json={"username": self.email, "uaid": "", "isOtherIdpSupported": True},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            exists = d.get("IfExistsResult", 1)
            if exists == 0:
                return self.found("Microsoft account found")
            if exists == 1:
                return self.not_found("No Microsoft account")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")
