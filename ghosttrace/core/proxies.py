from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ProxyConfig:
    use_tor: bool = False
    tor_socks: str = "socks5h://127.0.0.1:9050"
    proxy_url: Optional[str] = None

    def get_proxy(self) -> Optional[str]:
        if self.proxy_url:
            return self.proxy_url
        if self.use_tor:
            return self.tor_socks
        return None

    def as_aiohttp_proxy(self) -> Optional[str]:
        return self.get_proxy()

    def as_aiohttp_args(self) -> Dict[str, str]:
        proxy = self.as_aiohttp_proxy()
        return {"proxy": proxy} if proxy else {}


class ProxyClientSession:
    def __init__(self, session: Any, proxy: Optional[str] = None) -> None:
        self._session = session
        self._proxy = proxy

    async def __aenter__(self) -> "ProxyClientSession":
        await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._session.__aexit__(exc_type, exc, tb)

    def request(self, method: str, url: str, **kwargs):
        if self._proxy and "proxy" not in kwargs:
            kwargs["proxy"] = self._proxy
        return self._session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def __getattr__(self, name: str):
        return getattr(self._session, name)
