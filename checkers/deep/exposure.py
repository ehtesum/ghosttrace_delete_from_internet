import random
import re
import time

from checkers.base import BaseChecker


class GitHubCodeChecker(BaseChecker):
    ID, NAME = "github_code", "GitHub Public Code"
    PRIVACY, CATEGORY = "api", "developer"
    LAYER = "deep"
    DELETE_URL = ""

    def check(self):
        r = self._get(
            "https://api.github.com/search/code",
            params={"q": f'"{self.email}"', "per_page": 5},
            headers={"Accept": "application/vnd.github+json"},
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            d = r.json()
            count = d.get("total_count", 0)
            if count > 0:
                repos = list({i.get("repository", {}).get("full_name", "") for i in d.get("items", [])})
                return self.found(
                    f"Email appears in {count} public file(s)  |  Repos: {', '.join(repos[:3])}",
                    data=repos,
                )
            return self.not_found("Email not found in public code")
        if r.status_code == 403:
            return self.error("GitHub API rate limited")
        return self.unknown(f"HTTP {r.status_code}")


class PasteDorkChecker(BaseChecker):
    ID, NAME = "paste_dork", "Paste Sites (DDG)"
    PRIVACY, CATEGORY = "direct", "exposure"
    LAYER = "deep"
    DELETE_URL = ""

    QUERIES = [
        'site:pastebin.com',
        'site:gist.github.com',
        'site:ghostbin.co',
    ]

    def check(self):
        total = 0
        for site in self.QUERIES:
            r = self._get(
                "https://html.duckduckgo.com/html/",
                params={"q": f'"{self.email}" {site}'},
                headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            if r and r.status_code == 200:
                total += r.text.count('class="result__a"')
            time.sleep(random.uniform(0.25, 0.75))  # FIX BUG-44: fixed 0.4 s sleep fingerprinted by DDG rate limiter

        if total > 0:
            return self.found(f"~{total} paste/gist reference(s) found")
        return self.not_found("No paste site references found")
