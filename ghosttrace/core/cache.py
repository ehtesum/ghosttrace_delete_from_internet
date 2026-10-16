import time
from threading import Lock
from typing import Any, Dict, Optional


class TTLCache:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._store: Dict[str, Any] = {}
        self._expiry: Dict[str, float] = {}
        self._lock = Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            expiry = self._expiry.get(key)
            if expiry is None or expiry < time.time():
                self._store.pop(key, None)
                self._expiry.pop(key, None)
                return None
            return self._store.get(key)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = value
            self._expiry[key] = time.time() + self.ttl_seconds

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._expiry.clear()
