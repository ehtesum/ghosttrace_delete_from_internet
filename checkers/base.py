import hashlib
import time
from abc import ABC, abstractmethod

import requests


class BaseChecker(ABC):
    ID: str = ""
    NAME: str = ""
    PRIVACY: str = "direct"   # hash-md5 | api | direct | local
    CATEGORY: str = "services"
    DELETE_URL: str = ""
    LAYER: str = "surface"

    def __init__(self, email: str, session: requests.Session, **opts):
        self.email = email.strip().lower()
        self.session = session
        self.opts = opts

    # ── result builders ────────────────────────────────────────────────────

    def found(self, details="", data=None, delete_url=None):
        return self._build("found", details, data, delete_url)

    def not_found(self, details=""):
        return self._build("not_found", details)

    def unknown(self, details=""):
        return self._build("unknown", details)

    def error(self, details=""):
        return self._build("error", details)

    def requires_key(self, key_name="API key"):
        return self._build("requires_key", f"Requires {key_name} — see API Keys panel")

    def _build(self, status, details="", data=None, delete_url=None):
        return {
            "id": self.ID,
            "name": self.NAME,
            "status": status,
            "details": details,
            "privacy": self.PRIVACY,
            "category": self.CATEGORY,
            "layer": self.LAYER,
            "delete_url": delete_url or self.DELETE_URL,
            "data": data or [],
        }

    # ── http helpers ───────────────────────────────────────────────────────

    def _get(self, url, **kwargs):
        try:
            return self.session.get(url, timeout=12, **kwargs)
        except Exception:
            return None

    def _post(self, url, **kwargs):
        try:
            return self.session.post(url, timeout=12, **kwargs)
        except Exception:
            return None

    def _probe(self, url, payload, found_texts, not_found_texts, method="post", as_json=False):
        """Generic login/signup probe — returns True/False/None."""
        try:
            if method == "post":
                r = self.session.post(url, json=payload if as_json else None,
                                      data=None if as_json else payload, timeout=12)
            else:
                r = self.session.get(url, params=payload, timeout=12)
            text = r.text.lower()
            for t in found_texts:
                if t.lower() in text:
                    return True
            for t in not_found_texts:
                if t.lower() in text:
                    return False
            return None
        except Exception:
            return None

    # ── utilities ──────────────────────────────────────────────────────────

    def _md5(self, s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()

    @abstractmethod
    def check(self) -> dict:
        pass
