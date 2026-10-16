from checkers.base import BaseChecker


class GravatarChecker(BaseChecker):
    ID, NAME = "gravatar", "Gravatar"
    PRIVACY, CATEGORY = "hash-md5", "identity"
    DELETE_URL = "https://en.gravatar.com/delete"

    def check(self):
        r = self._get(f"https://www.gravatar.com/{self._md5(self.email)}.json")
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                name = r.json()["entry"][0].get("displayName", "")
                return self.found(f"Display name: {name}" if name else "Profile found")
            except Exception:
                return self.found("Profile found")
        if r.status_code == 404:
            return self.not_found("No Gravatar profile")
        return self.unknown(f"HTTP {r.status_code}")
