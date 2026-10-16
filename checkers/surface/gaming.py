from checkers.base import BaseChecker


class SteamChecker(BaseChecker):
    ID, NAME = "steam", "Steam"
    PRIVACY, CATEGORY = "direct", "gaming"
    DELETE_URL = "https://help.steampowered.com/en/faqs/view/4F3E-C054-C442-E64E"

    def check(self):
        r = self._get(
            "https://store.steampowered.com/join/checkavail/",
            params={"email": self.email, "kraken_version": "1"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            # bAvailable=true → NOT taken; false → taken
            avail = r.json().get("bAvailable", True)
            return self.not_found("Email not registered") if avail else self.found("Account registered")
        except Exception:
            return self.unknown(f"HTTP {r.status_code}")


class RobloxChecker(BaseChecker):
    ID, NAME = "roblox", "Roblox"
    PRIVACY, CATEGORY = "direct", "gaming"
    DELETE_URL = "https://en.help.roblox.com/hc/en-us/articles/203313050"

    def check(self):
        r = self._post(
            "https://auth.roblox.com/v1/validators/email",
            json={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            errs = r.json().get("errors", [])
            for e in errs:
                if e.get("code") == 2:
                    return self.found("Email already registered")
            return self.not_found("Email not registered")
        except Exception:
            return self.unknown(f"HTTP {r.status_code}")


class EpicGamesChecker(BaseChecker):
    ID, NAME = "epic_games", "Epic Games"
    PRIVACY, CATEGORY = "api", "gaming"
    DELETE_URL = "https://www.epicgames.com/help/en-US/epic-accounts-c5719348850459/general-support-c5719341353627/how-do-i-delete-my-epic-games-account-a5720459654027"

    def check(self):
        r = self._get(
            "https://www.epicgames.com/id/api/email/exists",
            params={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        try:
            if r.json().get("exists"):
                return self.found("Epic Games account found")
            return self.not_found("No account found")
        except Exception:
            return self.unknown(f"HTTP {r.status_code}")


class BattleNetChecker(BaseChecker):
    ID, NAME = "battle_net", "Battle.net"
    PRIVACY, CATEGORY = "direct", "gaming"
    DELETE_URL = "https://us.battle.net/support/en/article/77526"

    def check(self):
        r = self._post(
            "https://us.battle.net/login/en/login",
            json={"inputs": [{"input_id": "account_name", "value": self.email},
                              {"input_id": "password", "value": "GhostProbe9z!"}]},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            auth_url = d.get("authentication_message", "").lower()
            if "invalid password" in auth_url or "incorrect" in auth_url:
                return self.found("Account found (wrong password)")
            if "no account" in str(d).lower():
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown("Could not determine")
