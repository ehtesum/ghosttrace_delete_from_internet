from checkers.base import BaseChecker


class CanvaChecker(BaseChecker):
    ID, NAME = "canva", "Canva"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://www.canva.com/settings/account/delete"

    def check(self):
        r = self._post(
            "https://www.canva.com/api/v1/account/forgot-password",
            json={"email": self.email},
            headers={"Content-Type": "application/json",
                     "Origin": "https://www.canva.com"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            if d.get("success") or d.get("status") == "ok":
                return self.found("Account found (reset email sent)")
            err = str(d.get("error", d.get("message", ""))).lower()
            if "not found" in err or "no account" in err or "invalid" in err:
                return self.not_found("No account found")
        except Exception:
            pass
        text = r.text.lower()
        if "sent" in text or "check your email" in text:
            return self.found("Account found (reset email sent)")
        if "not found" in text or "no account" in text:
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class FigmaChecker(BaseChecker):
    ID, NAME = "figma", "Figma"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://help.figma.com/hc/en-us/articles/360040328654"

    def check(self):
        r = self._post(
            "https://www.figma.com/api/session/forgot_password",
            json={"email": self.email},
            headers={"Content-Type": "application/json",
                     "Origin": "https://www.figma.com"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            if d.get("meta") == "ok" or d.get("status") == 200:
                return self.found("Account found (reset email sent)")
            err = str(d.get("err", d.get("error", ""))).lower()
            if "not found" in err or "no account" in err:
                return self.not_found("No account found")
        except Exception:
            pass
        text = r.text.lower()
        if "sent" in text or "check your" in text:
            return self.found("Account found (reset email sent)")
        return self.unknown(f"HTTP {r.status_code}")


class UdemyChecker(BaseChecker):
    ID, NAME = "udemy", "Udemy"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://www.udemy.com/user/edit-account/"

    def check(self):
        r = self._post(
            "https://www.udemy.com/api-2.0/auth/udemy/forgot-password/send-email/",
            data={"email": self.email},
            headers={"Referer": "https://www.udemy.com/join/passwordless-auth/"},
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                d = r.json()
                if d.get("success") or d.get("status") == "success":
                    return self.found("Account found (reset email sent)")
                if d.get("detail") and "not found" in str(d.get("detail")).lower():
                    return self.not_found("No account found")
            except Exception:
                pass
            return self.found("Account found (reset email sent)")
        if r.status_code == 400:
            text = r.text.lower()
            if "not found" in text or "no account" in text:
                return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class CourseraChecker(BaseChecker):
    ID, NAME = "coursera", "Coursera"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://www.coursera.org/account-profile"

    def check(self):
        r = self._post(
            "https://accounts.coursera.org/api/v1/forgotPassword",
            json={"email": self.email},
            headers={"Content-Type": "application/json",
                     "Origin": "https://www.coursera.org"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            if d.get("success") or d.get("message", "").lower().startswith("email sent"):
                return self.found("Account found (reset email sent)")
            err = str(d.get("error", d.get("message", ""))).lower()
            if "not found" in err or "no account" in err or "invalid email" in err:
                return self.not_found("No account found")
        except Exception:
            pass
        text = r.text.lower()
        if "sent" in text or "check your" in text:
            return self.found("Account found (reset email sent)")
        return self.unknown(f"HTTP {r.status_code}")


class CoinbaseChecker(BaseChecker):
    ID, NAME = "coinbase", "Coinbase"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://help.coinbase.com/en/coinbase/managing-my-account/closing-deleting-account"

    def check(self):
        r = self._post(
            "https://login.coinbase.com/api/v1/auth/signin",
            json={"email": self.email, "password": "GhostProbe9z!"},
            headers={"Content-Type": "application/json",
                     "Origin": "https://login.coinbase.com"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            err = str(d.get("error", d.get("message", ""))).lower()
            if "password" in err and ("invalid" in err or "incorrect" in err or "wrong" in err):
                return self.found("Account found (wrong password)")
            if "not found" in err or "no account" in err or "doesn't exist" in err:
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class BinanceChecker(BaseChecker):
    ID, NAME = "binance", "Binance"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://www.binance.com/en/my/security/account-deletion"

    def check(self):
        r = self._post(
            "https://accounts.binance.com/bapi/accounts/v1/public/authcenter/reset/email/send",
            json={"email": self.email, "resetTokenType": "RESET_PASSWORD"},
            headers={"Content-Type": "application/json",
                     "Origin": "https://www.binance.com"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            code = d.get("code", "")
            msg = str(d.get("message", "")).lower()
            if code == "000000" or d.get("success"):
                return self.found("Account found (reset email sent)")
            if "not found" in msg or "invalid" in msg or "not exist" in msg:
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class BandcampChecker(BaseChecker):
    ID, NAME = "bandcamp", "Bandcamp"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://bandcamp.com/account_delete"

    def check(self):
        r = self._post(
            "https://bandcamp.com/login_email",
            data={"email": self.email, "password": "GhostProbe9z!"},
            headers={"Referer": "https://bandcamp.com/login",
                     "Origin": "https://bandcamp.com"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("incorrect" in text or "wrong" in text or "invalid" in text):
            return self.found("Account found (wrong password)")
        if "no account" in text or "email not found" in text or "not registered" in text:
            return self.not_found("No account found")
        try:
            d = r.json()
            err = str(d.get("error", "")).lower()
            if "password" in err:
                return self.found("Account found (wrong password)")
            if "email" in err and "not" in err:
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class DeezerChecker(BaseChecker):
    ID, NAME = "deezer", "Deezer"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://www.deezer.com/en/profile/delete"

    def check(self):
        r = self._post(
            "https://connect.deezer.com/oauth/login.php",
            data={"login": self.email, "password": "GhostProbe9z!",
                  "app_id": "1", "redirect_uri": "https://www.deezer.com/"},
            headers={"Referer": "https://www.deezer.com/",
                     "Origin": "https://www.deezer.com"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "wrong password" in text or ("password" in text and "incorrect" in text):
            return self.found("Account found (wrong password)")
        if "email not found" in text or "no account" in text or "not registered" in text:
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class KofiChecker(BaseChecker):
    ID, NAME = "kofi", "Ko-fi"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://ko-fi.com/manage/account"

    def check(self):
        r = self._post(
            "https://ko-fi.com/Account/Login",
            data={"Email": self.email, "Password": "GhostProbe9z!",
                  "__RequestVerificationToken": ""},
            headers={"Referer": "https://ko-fi.com/account/login",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "incorrect password" in text or "wrong password" in text or ("password" in text and "invalid" in text):
            return self.found("Account found (wrong password)")
        if "no account" in text or "email not found" in text or "not registered" in text:
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class GumroadChecker(BaseChecker):
    ID, NAME = "gumroad", "Gumroad"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://app.gumroad.com/settings/advanced"

    def check(self):
        r = self._post(
            "https://app.gumroad.com/login",
            data={"email": self.email, "password": "GhostProbe9z!"},
            headers={"Referer": "https://app.gumroad.com/login",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "wrong password" in text or "incorrect password" in text:
            return self.found("Account found (wrong password)")
        if "no account" in text or "not found" in text or "can't find" in text:
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class DevToChecker(BaseChecker):
    ID, NAME = "devto", "DEV.to"
    PRIVACY, CATEGORY = "api", "services"
    DELETE_URL = "https://dev.to/settings/account"

    def check(self):
        # DEV.to / Forem: try signup to see if email is taken
        r = self._post(
            "https://dev.to/users",
            json={"user": {"email": self.email, "username": "ghostprobe9z",
                           "password": "GhostProbe9z!",
                           "password_confirmation": "GhostProbe9z!"}},
            headers={"Content-Type": "application/json",
                     "Accept": "application/json",
                     "Origin": "https://dev.to"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            errs = str(d.get("error", d.get("errors", ""))).lower()
            if "email" in errs and ("taken" in errs or "already" in errs):
                return self.found("Email already registered")
            if "username" in errs and ("taken" in errs or "already" in errs):
                return self.unknown("Could not determine (username conflict)")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class AcademiaChecker(BaseChecker):
    ID, NAME = "academia", "Academia.edu"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://www.academia.edu/account/delete_account"

    def check(self):
        r = self._post(
            "https://www.academia.edu/password_resets",
            data={"email": self.email},
            headers={"Referer": "https://www.academia.edu/forgot_password",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "sent" in text or "check your" in text or "email" in text and "password" in text:
            return self.found("Account found (reset email sent)")
        if "not found" in text or "no account" in text or "couldn" in text:
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class LastFmChecker(BaseChecker):
    ID, NAME = "lastfm", "Last.fm"
    PRIVACY, CATEGORY = "direct", "media"
    DELETE_URL = "https://www.last.fm/settings/privacy"

    def check(self):
        r = self._post(
            "https://www.last.fm/login",
            data={"username_or_email": self.email, "password": "GhostProbe9z!",
                  "csrfmiddlewaretoken": ""},
            headers={"Referer": "https://www.last.fm/login",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "wrong password" in text or "incorrect password" in text or ("password" in text and "invalid" in text):
            return self.found("Account found (wrong password)")
        if "no account" in text or "not found" in text or "couldn" in text:
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class StackOverflowChecker(BaseChecker):
    ID, NAME = "stackoverflow", "Stack Overflow"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://stackoverflow.com/users/delete/current"

    def check(self):
        r = self._post(
            "https://stackoverflow.com/users/account-recovery",
            data={"email": self.email},
            headers={"Referer": "https://stackoverflow.com/users/account-recovery",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "sent" in text or "check your" in text or "email" in text and "recovery" in text:
            return self.found("Account found (recovery email sent)")
        if "not found" in text or "no account" in text:
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class HashNodeChecker(BaseChecker):
    ID, NAME = "hashnode", "Hashnode"
    PRIVACY, CATEGORY = "api", "services"
    DELETE_URL = "https://hashnode.com/settings"

    def check(self):
        # Hashnode has a public GraphQL API
        query = """
        mutation ForgotPassword($input: ForgotPasswordInput!) {
          forgotPassword(input: $input) { success }
        }
        """
        r = self._post(
            "https://gql.hashnode.com",
            json={"query": query,
                  "variables": {"input": {"email": self.email}}},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            data = d.get("data", {})
            if data.get("forgotPassword", {}).get("success"):
                return self.found("Account found (reset email sent)")
            errs = d.get("errors", [])
            for e in errs:
                msg = str(e.get("message", "")).lower()
                if "not found" in msg or "no account" in msg:
                    return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")
