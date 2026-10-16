from ...core.base_checker import BaseChecker


class ExampleUsernameChecker(BaseChecker):
    id = "example_username"
    name = "Example Username Checker"
    category = "testing"
    layer = "username"
    privacy = "direct"
    timeout = 12.0

    async def scan(self, query: str, session, config: dict) -> dict:
        return {
            "status": "not_found",
            "confidence": 40.0,
            "details": "Example username checker is a placeholder plugin.",
            "evidence": [],
            "links": [f"https://example.com/{query}"],
            "metadata": {},
            "raw": {"query": query, "config": config},
        }
