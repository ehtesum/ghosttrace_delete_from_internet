from urllib.parse import quote_plus

from checkers.base import BaseChecker


class HIBPChecker(BaseChecker):
    ID, NAME = "hibp", "Have I Been Pwned"
    PRIVACY, CATEGORY = "api", "breaches"
    DELETE_URL = "https://haveibeenpwned.com"

    def check(self):
        key = self.opts.get("hibp_key", "").strip()
        if not key:
            return self.requires_key("HIBP API key")
        r = self._get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(self.email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "User-Agent": "GhostTrace/2.0"},
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            b = r.json()
            names = ", ".join(x["Name"] for x in b[:6])
            extra = f" +{len(b)-6} more" if len(b) > 6 else ""
            return self.found(f"{len(b)} breach(es): {names}{extra}")
        if r.status_code == 404:
            return self.not_found("No breaches found")
        if r.status_code == 401:
            return self.error("Invalid HIBP API key")
        if r.status_code == 429:
            return self.error("Rate limited — wait a moment")
        return self.unknown(f"HTTP {r.status_code}")


class EmailRepChecker(BaseChecker):
    ID, NAME = "emailrep", "EmailRep.io"
    PRIVACY, CATEGORY = "api", "reputation"
    DELETE_URL = ""

    def check(self):
        key = self.opts.get("emailrep_key", "").strip()
        headers = {"Accept": "application/json", "User-Agent": "GhostTrace/2.0"}
        if key:
            headers["Key"] = key

        r = self._get(
            f"https://emailrep.io/{quote_plus(self.email)}",
            headers=headers,
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                d = r.json()
                profiles = d.get("details", {}).get("profiles", [])
                reputation = d.get("reputation", "none")
                if profiles:
                    return self.found(
                        f"Linked: {', '.join(profiles[:6])}  |  Reputation: {reputation}"
                    )
                return self.not_found(f"No linked profiles  |  Reputation: {reputation}")
            except Exception:
                return self.unknown(f"HTTP {r.status_code}")
        if r.status_code == 401:
            return self.error("Invalid EmailRep API key")
        if r.status_code == 403:
            return self.requires_key("EmailRep API key")
        if r.status_code == 429:
            if "unauthenticated api is currently disabled" in r.text.lower():
                return self.requires_key("EmailRep API key")
            return self.error("Rate limited")
        if r.status_code == 404:
            return self.not_found("No linked profiles found")
        return self.unknown(f"HTTP {r.status_code}")
