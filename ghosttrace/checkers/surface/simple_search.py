from ...core.base_checker import BaseChecker


class SimpleSearchChecker(BaseChecker):
    """A lightweight surface checker that attempts a harmless HTTP GET to
    a constructed URL and reports presence if the host returns a 200.

    This is a safe example implementation showing how to use aiohttp
    in an async checker without registering at import time.
    """

    id = "simple_search"
    name = "Simple Search Checker"
    category = "testing"
    layer = "surface"
    privacy = "direct"
    timeout = 8.0

    async def scan(self, query: str, session, config: dict) -> dict:
        # Construct a benign example URL (this is illustrative only)
        url = f"https://example.com/search?q={query}"
        try:
            async with session.get(url) as resp:
                status = resp.status
                if status == 200:
                    return {
                        "status": "found",
                        "confidence": 30.0,
                        "details": "Example host returned 200",
                        "evidence": [],
                        "links": [url],
                        "metadata": {},
                        "raw": {"status": status},
                    }
                return {"status": "not_found", "confidence": 5.0, "raw": {"status": status}}
        except Exception as exc:
            return {"status": "error", "confidence": 0.0, "details": str(exc), "raw": {"error": repr(exc)}}
