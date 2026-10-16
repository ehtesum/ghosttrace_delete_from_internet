from checkers.base import BaseChecker


class HudsonRockChecker(BaseChecker):
    ID, NAME = "hudson_rock", "Infostealer DB (Hudson Rock)"
    PRIVACY, CATEGORY = "api", "breaches"
    LAYER = "deep"
    DELETE_URL = ""

    def check(self):
        r = self._get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login",
            params={"email": self.email},
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                d = r.json()
                total = d.get("total", 0)
                if total > 0:
                    return self.found(
                        f"⚠ Found in {total} infostealer log(s) — credentials may be compromised!",
                        data=d.get("stealers", [])[:3],
                    )
                return self.not_found("Not found in infostealer databases")
            except Exception:
                pass
        if r.status_code == 429:
            return self.error("Rate limited")
        return self.unknown(f"HTTP {r.status_code}")


class LeakCheckChecker(BaseChecker):
    ID, NAME = "leakcheck", "LeakCheck.io"
    PRIVACY, CATEGORY = "api", "breaches"
    LAYER = "deep"
    DELETE_URL = ""

    def check(self):
        r = self._get("https://leakcheck.io/api/public", params={"check": self.email})
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                d = r.json()
                if d.get("found"):
                    count = d.get("found", 0)
                    sources = d.get("sources", [])[:5]
                    return self.found(
                        f"Found in {count} source(s): {', '.join(sources) if sources else 'details hidden'}",
                        data=sources,
                    )
                return self.not_found("Not found in LeakCheck database")
            except Exception:
                pass
        return self.unknown(f"HTTP {r.status_code}")


class BreachDirectoryChecker(BaseChecker):
    ID, NAME = "breach_directory", "BreachDirectory"
    PRIVACY, CATEGORY = "api", "breaches"
    LAYER = "deep"
    DELETE_URL = ""

    def check(self):
        r = self._get(
            "https://breachdirectory.org/api",
            params={"func": "auto", "term": self.email},
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                d = r.json()
                if d.get("found"):
                    results = d.get("result", [])
                    return self.found(f"Found in {len(results)} breach record(s)", data=results[:5])
                return self.not_found("Not found in BreachDirectory")
            except Exception:
                pass
        return self.unknown(f"HTTP {r.status_code}")
