"""
Dark web / Tor-based exposure checkers.
These require Tor to be running (socks5h://127.0.0.1:9050).
Falls back to clearnet mirrors where available.
"""
import json
from checkers.base import BaseChecker


class AhmiaChecker(BaseChecker):
    """
    Search Ahmia — the largest index of .onion sites.
    Uses the clearnet version (ahmia.fi) which proxies to the Tor index.
    """
    ID, NAME = "ahmia", "Ahmia Dark Web Index"
    PRIVACY, CATEGORY, LAYER = "api", "exposure", "deep"
    DELETE_URL = ""

    def check(self):
        r = self._get(
            "https://ahmia.fi/search/",
            params={"q": f'"{self.email}"'},
            headers={"Accept": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            text = r.text.lower()
            if self.email.lower() in text:
                return self.found("Email found in dark web index results", data=[
                    {"source": "Ahmia dark web index", "note": "Appears in indexed .onion content"}
                ])
            if "no results" in text or r.status_code == 200:
                return self.not_found("Not found in dark web index")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class IntelXChecker(BaseChecker):
    """
    IntelligenceX — indexes dark web, data breaches, public leaks.
    Uses their free public API (rate-limited, no key required for basic use).
    """
    ID, NAME = "intelx", "IntelligenceX"
    PRIVACY, CATEGORY, LAYER = "api", "breaches", "deep"
    DELETE_URL = "https://intelx.io/account"

    def check(self):
        # Public search via IntelX free tier
        r = self._post(
            "https://2.intelx.io/intelligent/search",
            json={
                "term": self.email,
                "maxresults": 5,
                "media": 0,
                "target": 0,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 2,
            },
            headers={"x-key": "00000000-0000-0000-0000-000000000000"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            sid = data.get("id", "")
            if not sid:
                return self.unknown("No search ID returned")

            # Fetch results
            r2 = self._get(
                "https://2.intelx.io/intelligent/search/result",
                params={"id": sid, "limit": 5},
                headers={"x-key": "00000000-0000-0000-0000-000000000000"},
            )
            if not r2:
                return self.unknown("Could not fetch results")
            res = r2.json()
            records = res.get("records", [])
            if records:
                sources = list({r.get("storageid", "")[:8] for r in records})
                return self.found(
                    f"{len(records)} record(s) found in IntelligenceX index",
                    data=[{"source": "IntelligenceX", "count": len(records), "ids": sources}],
                )
            return self.not_found("Not found in IntelligenceX")
        except Exception as e:
            return self.unknown(f"Parse error: {str(e)[:60]}")


class SnusbaseChecker(BaseChecker):
    """
    Snusbase breach database check via their public API.
    Free tier allows basic lookups.
    """
    ID, NAME = "snusbase", "Snusbase"
    PRIVACY, CATEGORY, LAYER = "api", "breaches", "deep"
    DELETE_URL = ""

    def check(self):
        r = self._post(
            "https://api.snusbase.com/data/search",
            json={"terms": [self.email], "types": ["email"], "wildcard": False},
            headers={"Auth": "free", "Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            data = r.json()
            if data.get("took") is not None:
                hits = data.get("size", 0)
                if hits and hits > 0:
                    return self.found(f"{hits} breach record(s) found in Snusbase")
                return self.not_found("Not found in Snusbase")
        except Exception:
            pass
        if r.status_code == 401:
            return self.requires_key("Snusbase API key")
        return self.unknown(f"HTTP {r.status_code}")


class DehashedChecker(BaseChecker):
    """
    Dehashed breach search — checks for email in aggregated data breaches.
    """
    ID, NAME = "dehashed", "Dehashed"
    PRIVACY, CATEGORY, LAYER = "api", "breaches", "deep"
    DELETE_URL = ""

    def check(self):
        r = self._get(
            "https://api.dehashed.com/search",
            params={"query": f"email:{self.email}", "size": 5},
            headers={"Accept": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        if r.status_code == 401:
            return self.requires_key("Dehashed API key")
        try:
            data = r.json()
            total = data.get("total", 0)
            if total and total > 0:
                return self.found(f"{total} breach record(s) in Dehashed")
            return self.not_found("Not found in Dehashed")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class OnionEmailChecker(BaseChecker):
    """
    Check if email appears in known dark web leak archives via Tor.
    Requires Tor running on 127.0.0.1:9050.
    """
    ID, NAME = "onion_leak", "Tor Leak Archives"
    PRIVACY, CATEGORY, LAYER = "api", "breaches", "deep"
    DELETE_URL = ""

    def check(self):
        # Try Tor check first
        try:
            from checkers.tor_proxy import tor_session, is_tor_available
        except ImportError:
            return self.error("tor_proxy module unavailable")

        tor = is_tor_available()
        if not tor["available"]:
            return self.unknown(f"Tor not available — {tor['message']}")

        s = tor_session()
        # Check via Tor-routed clearnet breach aggregator
        try:
            r = s.get(
                "https://api.proxynova.com/comb",
                params={"query": self.email},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                count = data.get("count", 0)
                if count and count > 0:
                    lines = data.get("lines", [])[:3]
                    return self.found(
                        f"{count} combination(s) found via Tor — email:password combos",
                        data=[{"line": l} for l in lines],
                    )
                return self.not_found("Not found in ProxyNova COMB database (via Tor)")
        except Exception as e:
            return self.unknown(f"Tor fetch error: {str(e)[:60]}")

        return self.unknown("No results from Tor sources")
