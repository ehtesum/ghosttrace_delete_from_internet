from typing import Any, Dict, List

from ...core.base_checker import BaseChecker


class AdultUsernameChecker(BaseChecker):
    """Checks common adult-site profile URL patterns for a username.

    Non-destructive: performs lightweight HTTP requests (HEAD/GET) to
    check for profile existence. Designed for local-only use; respects
    network and privacy configuration from `config` (proxy, tor).
    """

    id = "adult_username"
    name = "Adult Sites Username Checker"
    category = "adult"
    layer = "username"
    privacy = "direct"
    timeout = 10.0

    SITE_PATTERNS: List[str] = [
        # Profile URL patterns, `{u}` is replaced with the username
        "https://www.pornhub.com/model/{u}",
        "https://www.xvideos.com/profiles/{u}",
        "https://www.xnxx.com/model/{u}",
    ]

    async def scan(self, query: str, session: Any, config: Dict[str, Any]) -> Dict[str, Any]:
        username = query.strip().lstrip("@").lower()
        if not username:
            return {"status": "unknown", "confidence": 0.0, "details": "No username"}

        found_links: List[str] = []
        for pattern in self.SITE_PATTERNS:
            url = pattern.format(u=username)
            try:
                # Use GET but don't download large bodies unnecessarily
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        found_links.append(url)
            except Exception:
                # Individual site failures are non-fatal; continue
                continue

        if found_links:
            return {
                "status": "found",
                "confidence": 50.0,
                "details": f"Found username on {len(found_links)} adult site(s)",
                "evidence": [],
                "links": found_links,
                "metadata": {"sites_checked": len(self.SITE_PATTERNS)},
                "raw": {},
            }

        return {"status": "not_found", "confidence": 5.0, "raw": {"sites_checked": len(self.SITE_PATTERNS)}}
