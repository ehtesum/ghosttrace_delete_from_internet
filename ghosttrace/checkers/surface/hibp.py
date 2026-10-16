from typing import Any, Dict

from ...core.base_checker import BaseChecker


class HIBPChecker(BaseChecker):
    """Performs a read-only breach lookup against HaveIBeenPwned (HIBP).

    Requires `hibp_key` present in the scan `config`. If absent, returns a
    `requires_key` result. Non-destructive: uses the official API and honors
    response codes.
    """

    id = "hibp"
    name = "HaveIBeenPwned Breach Checker"
    category = "breach"
    layer = "surface"
    privacy = "api"
    requires_auth = True
    timeout = 20.0

    async def scan(self, query: str, session: Any, config: Dict[str, Any]) -> Dict[str, Any]:
        email = query.strip().lower()
        key = config.get("hibp_key") or config.get("hibp-key")
        if not key:
            return {"status": "requires_key", "confidence": 0.0, "details": "HIBP API key required"}

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true"
        headers = {"hibp-api-key": key, "User-Agent": "GhostTrace/4.0 (local)"}

        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    count = len(data) if isinstance(data, list) else 1
                    return {
                        "status": "found",
                        "confidence": min(90.0, 20.0 + count * 10.0),
                        "details": f"Found {count} breach(es)",
                        "evidence": [],
                        "links": [],
                        "metadata": {"count": count, "breaches": data},
                        "raw": {"status": resp.status},
                    }
                if resp.status == 404:
                    return {"status": "not_found", "confidence": 0.0, "raw": {"status": resp.status}}
                if resp.status in (401, 403):
                    return {"status": "error", "confidence": 0.0, "details": "Invalid or unauthorized HIBP API key", "raw": {"status": resp.status}}
                return {"status": "unknown", "confidence": 0.0, "details": f"HTTP {resp.status}", "raw": {"status": resp.status}}
        except Exception as exc:
            return {"status": "error", "confidence": 0.0, "details": str(exc), "raw": {"error": repr(exc)}}
