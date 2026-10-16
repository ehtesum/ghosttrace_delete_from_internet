from urllib.parse import quote_plus

from checkers.base import BaseChecker


class GitHubChecker(BaseChecker):
    ID, NAME = "github", "GitHub"
    PRIVACY, CATEGORY = "api", "developer"
    DELETE_URL = "https://github.com/settings/admin"

    def check(self):
        # Method 1: Profile email search (only works if email is public in GitHub settings)
        r = self._get(
            "https://api.github.com/search/users",
            params={"q": f"{self.email}+in:email", "per_page": 1},
            headers={"Accept": "application/vnd.github+json"},
        )
        if r and r.status_code == 200:
            d = r.json()
            if d.get("total_count", 0) > 0:
                uname = d["items"][0]["login"] if d.get("items") else "?"
                return self.found(f"Username: {uname}", delete_url=f"https://github.com/{uname}")
        elif r and r.status_code == 429:
            return self.error("GitHub API rate limited — wait a moment")

        # Method 2: Commit author email search — finds accounts even when email is private
        # in profile, as long as commits were pushed to public repos with the real email
        r2 = self._get(
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{self.email}", "per_page": 1},
            headers={"Accept": "application/vnd.github.cloak-preview+json"},
        )
        if r2 and r2.status_code == 200:
            d2 = r2.json()
            if d2.get("total_count", 0) > 0:
                items = d2.get("items", [])
                author = items[0].get("author") if items else None
                uname = author["login"] if author and author.get("login") else "?"
                return self.found(
                    f"Username: {uname} (found via commit history)",
                    delete_url=f"https://github.com/{uname}" if uname != "?" else self.DELETE_URL,
                )
            # Both searches returned 0 — could be no account OR private/noreply email
            return self.unknown(
                "Not found in public data — GitHub hides emails by default. "
                "Verify at github.com/settings/emails"
            )

        if not r:
            return self.error("Connection failed")
        return self.unknown(f"HTTP {r.status_code}")


class GitLabChecker(BaseChecker):
    ID, NAME = "gitlab", "GitLab"
    PRIVACY, CATEGORY = "api", "developer"
    DELETE_URL = "https://gitlab.com/-/profile/account"

    def check(self):
        r = self._get(
            "https://gitlab.com/api/v4/users",
            params={"search": self.email, "per_page": 1},
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            users = r.json()
            if users:
                uname = users[0].get("username", "?")
                return self.found(f"Username: {uname}")
            return self.not_found("No account found")
        return self.unknown(f"HTTP {r.status_code}")


class BitbucketChecker(BaseChecker):
    ID, NAME = "bitbucket", "Bitbucket"
    PRIVACY, CATEGORY = "api", "developer"
    DELETE_URL = "https://bitbucket.org/account/settings/"

    def check(self):
        r = self._get(
            "https://api.bitbucket.org/2.0/users",
            params={"q": f'account_id="{self.email}"'},
        )
        # Bitbucket doesn't expose email search publicly; try signup validation
        r2 = self._post(
            "https://bitbucket.org/account/signup/",
            data={"email": self.email},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        if not r2:
            return self.error("Connection failed")
        text = r2.text.lower()
        if "already" in text or "taken" in text or "registered" in text:
            return self.found("Email already registered")
        if "available" in text:
            return self.not_found("Email not registered")
        return self.unknown("Could not determine (anti-bot)")
