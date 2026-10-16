from checkers.base import BaseChecker


class SpotifyChecker(BaseChecker):
    ID, NAME = "spotify", "Spotify"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://support.spotify.com/article/close-account/"

    def check(self):
        r = self._get(
            "https://spclient.wg.spotify.com/signup/public/v1/account",
            params={"validate": "1", "email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            status = r.json().get("status", -1)
            if status == 20:
                return self.found("Email already registered")
            if status == 0:
                return self.not_found("Email not registered")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class SoundCloudChecker(BaseChecker):
    ID, NAME = "soundcloud", "SoundCloud"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://help.soundcloud.com/hc/en-us/articles/115003562548"

    def check(self):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://soundcloud.com/signin",
            "X-Requested-With": "XMLHttpRequest",
        }
        r = self._post(
            "https://api-auth.soundcloud.com/web-auth/sign-in/password",
            json={"client_id": "2t9loNQH90kzJcsFCODdigxfp325aq4z",
                  "email": self.email, "password": "ghost_probe_x9z"},
            headers=headers,
        )
        if r and r.status_code == 405:
            r = self._post(
                "https://api-auth.soundcloud.com/web-auth/sign-in/password",
                data={"client_id": "2t9loNQH90kzJcsFCODdigxfp325aq4z",
                      "email": self.email, "password": "ghost_probe_x9z"},
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            )
        if not r:
            return self.error("Connection failed")
        try:
            err = str(r.json().get("error", "")).lower()
            if "password" in err:
                return self.found("Account found (wrong password)")
            if "user" in err and "not" in err:
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class TwitchChecker(BaseChecker):
    ID, NAME = "twitch", "Twitch"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://www.twitch.tv/user/delete-account"

    def check(self):
        # Try GQL login probe (Twitch's own client uses this)
        r = self._post(
            "https://gql.twitch.tv/gql",
            json=[{"operationName": "core_ActionsCurrentUser_Query",
                   "variables": {},
                   "extensions": {"persistedQuery": {"version": 1,
                       "sha256Hash": "9cdfc5ebf8ee497e49f6a30823a822e7e9c5f91200fbe5b38f498adb4b20e4ef"}}}],
            headers={"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko",
                     "Content-Type": "application/json"},
        )
        # Fallback to legacy login endpoint
        r2 = self._post(
            "https://passport.twitch.tv/login",
            json={"client_id": "kimne78kx3ncx6brgo4mv6wki5h1ko",
                  "undelete_user": False,
                  "username": self.email,
                  "password": "GhostProbe9z!",
                  "authy_token": ""},
            headers={"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko",
                     "Content-Type": "application/json"},
        )
        if r2:
            try:
                d = r2.json()
                code = d.get("error_code", 0)
                # 3003 = wrong password (account exists), 3001 = user not found
                if code == 3003:
                    return self.found("Account found (wrong password)")
                if code in (3001, 3011):
                    return self.not_found("No account found")
            except Exception:
                pass
            if r2.status_code == 404:
                return self.unknown("Twitch endpoint changed or blocked")
        if not r2:
            return self.error("Connection failed")
        return self.unknown(f"HTTP {r2.status_code}")


class VimeoChecker(BaseChecker):
    ID, NAME = "vimeo", "Vimeo"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://vimeo.com/settings/account"

    def check(self):
        r = self._post(
            "https://vimeo.com/log_in",
            data={"email": self.email, "password": "GhostProbe9z!", "token": ""},
            headers={"Referer": "https://vimeo.com/log_in", "X-Requested-With": "XMLHttpRequest"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("wrong" in text or "incorrect" in text):
            return self.found("Account found (wrong password)")
        if "no account" in text or "not found" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine")


class DuolingoChecker(BaseChecker):
    ID, NAME = "duolingo", "Duolingo"
    PRIVACY, CATEGORY = "api", "services"
    DELETE_URL = "https://support.duolingo.com/hc/en-us/articles/205483550"

    def check(self):
        r = self._get("https://www.duolingo.com/2017-06-30/users",
                      params={"email": self.email})
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                users = r.json().get("users", [])
                if users:
                    uname = users[0].get("username", "?")
                    return self.found(f"Username: {uname}")
                return self.not_found("No account found")
            except Exception:
                pass
        return self.unknown(f"HTTP {r.status_code}")
