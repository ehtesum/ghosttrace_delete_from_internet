import hashlib
import requests
import time
from urllib.parse import quote_plus


class EmailChecker:
    CHECKS = [
        # (id, display_name, method_name, privacy_level, category, delete_url)
        ("gravatar",   "Gravatar",          "check_gravatar",   "hash-md5", "identity",      "https://en.gravatar.com/delete"),
        ("github",     "GitHub",            "check_github",     "api",      "developer",     "https://github.com/settings/admin"),
        ("hibp",       "Have I Been Pwned", "check_hibp",       "api",      "breaches",      "https://haveibeenpwned.com"),
        ("emailrep",   "EmailRep.io",       "check_emailrep",   "api",      "reputation",    ""),
        ("spotify",    "Spotify",           "check_spotify",    "direct",   "media",         "https://support.spotify.com/article/close-account/"),
        ("duolingo",   "Duolingo",          "check_duolingo",   "direct",   "services",      "https://support.duolingo.com/hc/en-us/articles/205483550"),
        ("twitter",    "Twitter / X",       "check_twitter",    "direct",   "social",        "https://help.twitter.com/en/managing-your-account/how-to-deactivate-twitter-account"),
        ("instagram",  "Instagram",         "check_instagram",  "direct",   "social",        "https://help.instagram.com/370452623149242"),
        ("reddit",     "Reddit",            "check_reddit",     "direct",   "social",        "https://www.reddit.com/settings/"),
        ("pinterest",  "Pinterest",         "check_pinterest",  "direct",   "social",        "https://help.pinterest.com/en/article/deactivate-or-close-your-account"),
        ("discord",    "Discord",           "check_discord",    "direct",   "social",        "https://support.discord.com/hc/en-us/articles/212500837"),
        ("adobe",      "Adobe",             "check_adobe",      "direct",   "services",      "https://helpx.adobe.com/manage-account/using/delete-adobe-account.html"),
        ("dropbox",    "Dropbox",           "check_dropbox",    "direct",   "services",      "https://help.dropbox.com/delete-restore/how-to-delete-account"),
        ("patreon",    "Patreon",           "check_patreon",    "direct",   "services",      "https://support.patreon.com/hc/en-us/articles/204606315"),
        ("tumblr",     "Tumblr",            "check_tumblr",     "direct",   "social",        "https://tumblr.com/account/delete"),
        ("wordpress",  "WordPress.com",     "check_wordpress",  "direct",   "services",      "https://wordpress.com/me/account"),
        ("twitch",     "Twitch",            "check_twitch",     "direct",   "media",         "https://www.twitch.tv/user/delete-account"),
        ("ebay",       "eBay",              "check_ebay",       "direct",   "commerce",      "https://www.ebay.com/help/account/closing-account/closing-your-ebay-account"),
        ("myspace",    "Myspace",           "check_myspace",    "direct",   "social",        "https://myspace.com/settings/delete"),
        ("soundcloud", "SoundCloud",        "check_soundcloud", "direct",   "media",         "https://help.soundcloud.com/hc/en-us/articles/115003562548"),
    ]

    def __init__(self, email: str, hibp_key: str = ""):
        self.email = email.strip().lower()
        self.hibp_key = hibp_key.strip()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        })

    # ── helpers ─────────────────────────────────────────────────────────────

    def _md5(self, s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()

    def _get(self, url, **kwargs) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=12, **kwargs)
        except Exception:
            return None

    def _post(self, url, **kwargs) -> requests.Response | None:
        try:
            return self.session.post(url, timeout=12, **kwargs)
        except Exception:
            return None

    # ── public API ───────────────────────────────────────────────────────────

    def check_all(self):
        total = len(self.CHECKS)
        for i, (cid, name, method_name, privacy, category, delete_url) in enumerate(self.CHECKS):
            yield {"type": "progress", "current": i + 1, "total": total, "checking": name}
            try:
                result = getattr(self, method_name)()
            except Exception:
                result = {"status": "error", "details": "Unexpected error"}

            yield {
                "type": "result",
                "id": cid,
                "name": name,
                "status": result.get("status", "unknown"),
                "details": result.get("details", ""),
                "privacy": privacy,
                "category": category,
                "delete_url": result.get("delete_url", delete_url),
            }
            time.sleep(0.4)

        yield {"type": "done"}

    # ── individual checks ────────────────────────────────────────────────────

    def check_gravatar(self):
        email_hash = self._md5(self.email)
        r = self._get(f"https://www.gravatar.com/{email_hash}.json")
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        if r.status_code == 200:
            try:
                name = r.json()["entry"][0].get("displayName", "")
                return {"status": "found", "details": f"Display name: {name}" if name else "Profile found"}
            except Exception:
                return {"status": "found", "details": "Profile found"}
        if r.status_code == 404:
            return {"status": "not_found", "details": "No Gravatar profile"}
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_github(self):
        r = self._get(
            "https://api.github.com/search/users",
            params={"q": f"{self.email}+in:email", "per_page": 1},
            headers={"Accept": "application/vnd.github+json"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        if r.status_code == 200:
            data = r.json()
            count = data.get("total_count", 0)
            if count > 0:
                username = data["items"][0]["login"] if data.get("items") else "?"
                return {"status": "found", "details": f"Username: {username}", "delete_url": f"https://github.com/{username}"}
            return {"status": "not_found", "details": "No account found"}
        if r.status_code == 422:
            return {"status": "unknown", "details": "Rate limited or invalid query"}
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_hibp(self):
        if not self.hibp_key:
            return {"status": "requires_key", "details": "Enter your HIBP API key (free at haveibeenpwned.com/API/Key)"}
        r = self._get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(self.email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": self.hibp_key, "User-Agent": "GhostTrace/1.0"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        if r.status_code == 200:
            breaches = r.json()
            names = ", ".join(b["Name"] for b in breaches[:6])
            extra = f" (+{len(breaches)-6} more)" if len(breaches) > 6 else ""
            return {"status": "found", "details": f"{len(breaches)} breach(es): {names}{extra}"}
        if r.status_code == 404:
            return {"status": "not_found", "details": "No breaches found"}
        if r.status_code == 401:
            return {"status": "error", "details": "Invalid HIBP API key"}
        if r.status_code == 429:
            return {"status": "error", "details": "Rate limited — try again in a moment"}
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_emailrep(self):
        r = self._get(f"https://emailrep.io/{quote_plus(self.email)}")
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        if r.status_code == 200:
            data = r.json()
            profiles = data.get("details", {}).get("profiles", [])
            suspicious = data.get("suspicious", False)
            reputation = data.get("reputation", "none")
            if profiles:
                return {"status": "found", "details": f"Linked profiles: {', '.join(profiles[:8])}  |  Reputation: {reputation}"}
            return {"status": "not_found", "details": f"No linked profiles  |  Suspicious: {suspicious}  |  Reputation: {reputation}"}
        if r.status_code == 429:
            return {"status": "error", "details": "Rate limited"}
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_spotify(self):
        r = self._get(
            "https://spclient.wg.spotify.com/signup/public/v1/account",
            params={"validate": "1", "email": self.email},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            status = data.get("status", -1)
            if status == 20:
                return {"status": "found", "details": "Email already registered"}
            if status == 0:
                return {"status": "not_found", "details": "Email available (not registered)"}
        except Exception:
            pass
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_duolingo(self):
        r = self._get("https://www.duolingo.com/2017-06-30/users", params={"email": self.email})
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        if r.status_code == 200:
            try:
                users = r.json().get("users", [])
                if users:
                    username = users[0].get("username", "?")
                    return {"status": "found", "details": f"Username: {username}"}
                return {"status": "not_found", "details": "No account found"}
            except Exception:
                pass
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_twitter(self):
        r = self._get(
            "https://api.twitter.com/i/users/email_available.json",
            params={"email": self.email},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            taken = not data.get("valid", True)
            if taken:
                return {"status": "found", "details": "Email is registered"}
            return {"status": "not_found", "details": "Email not registered"}
        except Exception:
            pass
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_instagram(self):
        r = self._get(
            "https://www.instagram.com/api/v1/users/lookup/",
            params={"q": self.email, "skip_recovery": "1"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        if r.status_code == 200:
            try:
                data = r.json()
                if data.get("user_found"):
                    obfuscated = data.get("obfuscated_email", "")
                    return {"status": "found", "details": f"Account found  {('| ' + obfuscated) if obfuscated else ''}".strip()}
                return {"status": "not_found", "details": "No account found"}
            except Exception:
                pass
        if r.status_code == 400:
            return {"status": "not_found", "details": "No account found"}
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_reddit(self):
        r = self._post(
            "https://www.reddit.com/api/check_username.json",
            data={"user": self.email},
            headers={"Origin": "https://www.reddit.com", "Referer": "https://www.reddit.com/login"},
        )
        # Reddit doesn't expose email lookup directly; we check signup instead
        r = self._post(
            "https://www.reddit.com/api/register",
            data={"email": self.email, "op": "reg", "user": "test__", "passwd": "", "passwd2": ""},
            headers={"Origin": "https://www.reddit.com"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            errors = r.json().get("json", {}).get("errors", [])
            for e in errors:
                if "email" in str(e).lower() and ("taken" in str(e).lower() or "used" in str(e).lower()):
                    return {"status": "found", "details": "Email already registered"}
        except Exception:
            pass
        return {"status": "unknown", "details": "Could not determine (anti-bot measures)"}

    def check_pinterest(self):
        r = self._get(
            "https://www.pinterest.com/resource/EmailExistsResource/get/",
            params={"source_url": "/", "data": f'{{"options":{{"email":"{self.email}"}}}}'},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            exists = data.get("resource_response", {}).get("data", False)
            if exists:
                return {"status": "found", "details": "Email registered"}
            return {"status": "not_found", "details": "Email not registered"}
        except Exception:
            pass
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_discord(self):
        r = self._post(
            "https://discord.com/api/v9/auth/register",
            json={"email": self.email, "username": "ghost", "password": "Gh0stTrace!", "consent": True},
            headers={"Content-Type": "application/json", "Origin": "https://discord.com"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            email_errors = data.get("email", [])
            for msg in email_errors:
                if "already" in str(msg).lower() or "registered" in str(msg).lower():
                    return {"status": "found", "details": "Email already registered"}
        except Exception:
            pass
        if r.status_code in (400, 429):
            return {"status": "unknown", "details": "Anti-bot protection active"}
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}

    def check_adobe(self):
        r = self._post(
            "https://auth.services.adobe.com/en_US/index.html#",
            data={"email": self.email},
        )
        r = self._get(
            f"https://auth.services.adobe.com/en_US/index.html?client_id=homepage&scope=openid,AdobeID&response_type=token&redirect_uri=https%3A%2F%2Fwww.adobe.com%2F",
        )
        # Use IMS public check endpoint
        r = self._get(
            "https://ims-na1.adobelogin.com/ims/check/v3/token",
            params={"client_id": "adobeid", "email": self.email},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            if "email" in data:
                return {"status": "found", "details": "Adobe ID found"}
        except Exception:
            pass
        return {"status": "unknown", "details": "Could not determine"}

    def check_dropbox(self):
        r = self._post(
            "https://www.dropbox.com/ajax_login",
            data={"login_email": self.email, "login_password": "wrongpass", "t": ""},
            headers={"Referer": "https://www.dropbox.com/login"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            text = r.text.lower()
            if "no account found" in text or "can't find" in text:
                return {"status": "not_found", "details": "No Dropbox account"}
            if "wrong password" in text or "incorrect password" in text or "enter your password" in text:
                return {"status": "found", "details": "Account exists (wrong password response)"}
        except Exception:
            pass
        return {"status": "unknown", "details": "Could not determine"}

    def check_patreon(self):
        r = self._post(
            "https://www.patreon.com/api/login",
            json={"email": self.email, "password": "ghost_trace_probe"},
            headers={"Content-Type": "application/json", "Origin": "https://www.patreon.com"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            text = r.text.lower()
            if "password" in text and ("incorrect" in text or "wrong" in text):
                return {"status": "found", "details": "Account found (wrong password)"}
            if "no account" in text or "not found" in text or "doesn't exist" in text:
                return {"status": "not_found", "details": "No account found"}
        except Exception:
            pass
        return {"status": "unknown", "details": "Could not determine"}

    def check_tumblr(self):
        r = self._post(
            "https://www.tumblr.com/api/v2/user/login",
            json={"email": self.email, "password": "ghost_probe"},
            headers={"Content-Type": "application/json"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            error = str(data.get("meta", {}).get("msg", "")).lower()
            if "password" in error or "incorrect" in error:
                return {"status": "found", "details": "Account found (wrong password)"}
            if "not found" in error or "no account" in error:
                return {"status": "not_found", "details": "No account found"}
        except Exception:
            pass
        return {"status": "unknown", "details": "Could not determine"}

    def check_wordpress(self):
        r = self._post(
            "https://wordpress.com/wp-login.php",
            data={"log": self.email, "pwd": "ghost_probe", "wp-submit": "Log+In"},
            headers={"Referer": "https://wordpress.com/log-in"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        text = r.text.lower()
        if "incorrect password" in text or "wrong password" in text:
            return {"status": "found", "details": "Account found (wrong password)"}
        if "no account" in text or "invalid username" in text:
            return {"status": "not_found", "details": "No account found"}
        return {"status": "unknown", "details": "Could not determine"}

    def check_twitch(self):
        r = self._post(
            "https://passport.twitch.tv/login",
            json={"login": self.email, "password": "ghost_probe_pass"},
            headers={"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko", "Content-Type": "application/json"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            error_code = data.get("error_code", 0)
            # 3001 = invalid login, 3003 = wrong password (account exists)
            if error_code == 3003:
                return {"status": "found", "details": "Account found (wrong password)"}
            if error_code == 3001:
                return {"status": "not_found", "details": "No account found"}
        except Exception:
            pass
        return {"status": "unknown", "details": "Could not determine"}

    def check_ebay(self):
        r = self._post(
            "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn",
            data={"userid": self.email, "pass": "ghost_probe"},
            headers={"Referer": "https://signin.ebay.com/"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        text = r.text.lower()
        if "password" in text and ("incorrect" in text or "wrong" in text):
            return {"status": "found", "details": "Account found (wrong password)"}
        if "no account" in text or "can't find" in text:
            return {"status": "not_found", "details": "No account found"}
        return {"status": "unknown", "details": "Could not determine"}

    def check_myspace(self):
        r = self._post(
            "https://myspace.com/ajax/login/",
            data={"email": self.email, "password": "ghost_probe"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        text = r.text.lower()
        if "invalid" in text and "password" in text:
            return {"status": "found", "details": "Account found (wrong password)"}
        if "not found" in text or "no account" in text:
            return {"status": "not_found", "details": "No account found"}
        return {"status": "unknown", "details": "Could not determine"}

    def check_soundcloud(self):
        r = self._post(
            "https://api-auth.soundcloud.com/web-auth/sign-in/password",
            json={"client_id": "2t9loNQH90kzJcsFCODdigxfp325aq4z", "email": self.email, "password": "ghost_probe"},
            headers={"Content-Type": "application/json"},
        )
        if r is None:
            return {"status": "error", "details": "Connection failed"}
        try:
            data = r.json()
            if r.status_code == 401:
                err = str(data.get("error", "")).lower()
                if "password" in err:
                    return {"status": "found", "details": "Account found (wrong password)"}
                if "user" in err and "not" in err:
                    return {"status": "not_found", "details": "No account found"}
        except Exception:
            pass
        return {"status": "unknown", "details": f"HTTP {r.status_code}"}
