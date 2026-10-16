from ...core.base_checker import BaseChecker


class ExampleSurfaceChecker(BaseChecker):
    id = "example_surface"
    name = "Example Surface Checker"
    category = "testing"
    layer = "surface"
    privacy = "direct"
    timeout = 12.0

    async def scan(self, query: str, session, config: dict) -> dict:
        return {
            "status": "not_found",
            "confidence": 35.0,
            "details": "Example surface checker is a placeholder plugin.",
            "evidence": [],
            "links": [],
            "metadata": {},
            "raw": {"query": query, "config": config},
        }
