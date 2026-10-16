import hashlib
from typing import Any, Dict

from ...core.base_checker import BaseChecker


class GravatarChecker(BaseChecker):
    """Checks for a Gravatar profile image for the email address.

    Non-destructive: performs a GET against gravatar with `d=404` to
    determine presence without downloading large payloads.
    """

    id = "gravatar"
    name = "Gravatar Presence Checker"
    category = "identity"
    layer = "surface"
    privacy = "direct"
    timeout = 8.0

    async def scan(self, query: str, session: Any, config: Dict[str, Any]) -> Dict[str, Any]:
        email = query.strip().lower()
        if not email or "@" not in email:
            return {"status": "unknown", "confidence": 0.0, "details": "Invalid email"}

        h = hashlib.md5(email.encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"

        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return {
                        "status": "found",
                        "confidence": 45.0,
                        "details": "Gravatar image found",
                        "evidence": [],
                        "links": [url],
                        "metadata": {"hash": h},
                        "raw": {"status": resp.status},
                    }
                if resp.status == 404:
                    return {"status": "not_found", "confidence": 5.0, "raw": {"status": resp.status}}
                return {"status": "unknown", "confidence": 0.0, "raw": {"status": resp.status}}
        except Exception as exc:
            return {"status": "error", "confidence": 0.0, "details": str(exc), "raw": {"error": repr(exc)}}
