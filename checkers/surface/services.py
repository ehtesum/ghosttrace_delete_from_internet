from checkers.base import BaseChecker


class AdobeChecker(BaseChecker):
    ID, NAME = "adobe", "Adobe"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://helpx.adobe.com/manage-account/using/delete-adobe-account.html"

    def check(self):
        r = self._get(
            "https://ims-na1.adobelogin.com/ims/check/v3/token",
            params={"client_id": "adobeid", "email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            # A valid Adobe ID response contains userId/id — not just any 200
            if d.get("userId") or d.get("id") or d.get("userAccount"):
                return self.found("Adobe ID found")
            ec = str(d.get("error_code", d.get("errorCode", ""))).lower()
            if any(x in ec for x in ("not_found", "invalid_email", "user_not_found")):
                return self.not_found("No Adobe ID found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class DropboxChecker(BaseChecker):
    ID, NAME = "dropbox", "Dropbox"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://help.dropbox.com/delete-restore/how-to-delete-account"

    def check(self):
        r = self._post(
            "https://www.dropbox.com/ajax_login",
            data={"login_email": self.email, "login_password": "GhostProbe9z!", "t": ""},
            headers={
                "Referer": "https://www.dropbox.com/login",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "no account" in text or "can't find" in text:
            return self.not_found("No Dropbox account")
        if "wrong password" in text or "incorrect" in text:
            return self.found("Account exists (wrong password)")
        return self.unknown("Could not determine")


class ZoomChecker(BaseChecker):
    ID, NAME = "zoom", "Zoom"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://support.zoom.us/hc/en-us/articles/201363243"

    def check(self):
        r = self._post(
            "https://zoom.us/signin",
            data={"email": self.email, "password": "GhostProbe9z!"},
            headers={"Referer": "https://zoom.us/signin"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("incorrect" in text or "wrong" in text):
            return self.found("Account found (wrong password)")
        if "no account" in text or "invalid email" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine")


class MediumChecker(BaseChecker):
    ID, NAME = "medium", "Medium"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://help.medium.com/hc/en-us/articles/115004182567"

    def check(self):
        r = self._post(
            "https://medium.com/m/signin",
            json={"email": self.email, "operationName": "SignIn"},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "email" in text and "sent" in text:
            return self.found("Account found (sign-in email sent)")
        if "no account" in text or "not found" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine")


class WordPressChecker(BaseChecker):
    ID, NAME = "wordpress", "WordPress.com"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://wordpress.com/me/account"

    def check(self):
        self._get("https://wordpress.com/log-in", headers={"Referer": "https://wordpress.com/"})
        r = self._post(
            "https://wordpress.com/wp-login.php",
            data={"log": self.email, "pwd": "GhostProbe9z!", "wp-submit": "Log+In", "redirect_to": "https://wordpress.com"},
            headers={"Referer": "https://wordpress.com/log-in/", "Content-Type": "application/x-www-form-urlencoded"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "incorrect password" in text or "wrong password" in text:
            return self.found("Account found (wrong password)")
        if "invalid username" in text or "unknown username" in text or "user does not exist" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine")


class PatreonChecker(BaseChecker):
    ID, NAME = "patreon", "Patreon"
    PRIVACY, CATEGORY = "direct", "services"
    DELETE_URL = "https://support.patreon.com/hc/en-us/articles/212500637"

    def check(self):
        import json as _json

        headers = {
            "Origin": "https://www.patreon.com",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }
        payload = {"data": {"email": self.email, "password": "GhostProbe9z!"}}
        r = self._post(
            "https://www.patreon.com/api/login",
            json=payload,
            headers=headers,
        )
        if r and r.status_code in (400, 405):
            r = self._post(
                "https://www.patreon.com/api/login",
                data={"data": _json.dumps(payload["data"])},
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            errors = str(data.get("errors", [])).lower()
            if "captcha" in errors:
                return self.unknown("Anti-bot protection active")
            if "invalid user" in errors or "incorrect email or password" in errors:
                return self.unknown("Could not determine")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class DiscordChecker(BaseChecker):
    ID, NAME = "discord", "Discord"
    PRIVACY, CATEGORY = "direct", "social"
    DELETE_URL = "https://support.discord.com/hc/en-us/articles/212500837"

    def check(self):
        r = self._post(
            "https://discord.com/api/v9/auth/register",
            json={"email": self.email, "username": "ghosttest", "password": "GhostProbe9z!",
                  "consent": True, "date_of_birth": "1990-01-01"},
            headers={"Content-Type": "application/json", "Origin": "https://discord.com"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            errors = []
            email_err = data.get("email")
            if isinstance(email_err, (list, tuple)):
                errors.extend(email_err)
            elif isinstance(email_err, str):
                errors.append(email_err)

            errs = data.get("errors") or {}
            if isinstance(errs, dict):
                for value in errs.values():
                    if isinstance(value, (list, tuple)):
                        errors.extend(value)
                    else:
                        errors.append(value)

            for e in errors:
                value = str(e).lower()
                if "already" in value or "in use" in value:
                    return self.found("Email already registered")
                if "captcha" in value or "hcaptcha" in value:
                    return self.unknown("Anti-bot protection active")
        except Exception:
            pass
        if r.status_code == 429:
            return self.unknown("Anti-bot protection active")
        return self.unknown("Could not determine")
