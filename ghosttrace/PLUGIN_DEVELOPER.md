GhostTrace Plugin Developer Guide
=================================

Overview
--------
Plugins (checkers) are lightweight Python modules that define one or more
`BaseChecker` subclasses. Plugins must NOT perform registration at import
time — the registry discovers, imports, and instantiates checkers during
application startup.

Location
--------
Place plugins under the `ghosttrace.checkers` package. Organize by layer
(e.g. `surface`, `deep`, `username`, `phone`, `image`, `domains`). Example
path: `ghosttrace/checkers/surface/my_checker.py`.

Minimal checker example
-----------------------

from ghosttrace.core.base_checker import BaseChecker

class MyChecker(BaseChecker):
    id = "my_checker"
    name = "My Checker"
    category = "testing"
    layer = "surface"

    async def scan(self, query: str, session, config: dict) -> dict:
        # perform async http calls using the provided aiohttp session
        return {"status": "not_found", "confidence": 0.0}

Rules
-----
- Do not import `ghosttrace.core.registry` or call `registry.register`.
- Keep imports limited and avoid heavy runtime side-effects at import time.
- Use the provided `session` (aiohttp.ClientSession) for network I/O.
- Catch exceptions and return a structured result with `status: "error"`.
- Provide `id` or `name` so the registry can deduplicate checkers.

Result format
-------------
Return a dict matching `CheckResult` fields, for example:

{
  "status": "found" | "not_found" | "unknown" | "error",
  "confidence": 0.0,
  "evidence": [],
  "links": [],
  "metadata": {},
  "raw": {},
  "details": "Human readable details"
}

Testing
-------
- Unit-test your checker by instantiating the class and calling `asyncio.run(checker.scan(...))`.
- Use the registry tests as a template for plugin isolation and discovery.

Troubleshooting
---------------
- If your plugin raises during import, the registry will log the error and continue.
- Ensure your checker does not execute network calls at import time.
