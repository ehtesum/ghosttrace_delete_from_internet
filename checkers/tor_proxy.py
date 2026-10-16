"""
Tor proxy session factory.
Routes all HTTP/HTTPS requests through a local Tor SOCKS5 proxy (default: 127.0.0.1:9050).
Also enables .onion resolution (socks5h = hostname-via-proxy).

Requirements:
  - Tor daemon or Tor Browser running locally
  - pip install PySocks
"""
import requests

TOR_SOCKS = "socks5h://127.0.0.1:9050"


def tor_session(base_session: requests.Session | None = None) -> requests.Session:
    """Return a requests Session routed through Tor. Inherits headers from base_session if given."""
    s = requests.Session()
    s.proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
    if base_session:
        s.headers.update(base_session.headers)
    return s


def is_tor_available() -> dict:
    """
    Quick check: can we reach the Tor check page via our proxy?
    Returns {"available": bool, "ip": str or None, "message": str}
    """
    result = {"available": False, "ip": None, "message": ""}
    try:
        s = tor_session()
        r = s.get("https://check.torproject.org/api/ip", timeout=12)
        data = r.json()
        if data.get("IsTor"):
            result["available"] = True
            result["ip"] = data.get("IP", "unknown")
            result["message"] = f"Tor active — exit node IP: {result['ip']}"
        else:
            result["message"] = "Connected but Tor flag not set — proxy may not be Tor"
    except Exception as e:
        result["message"] = f"Tor not reachable: {str(e)[:80]} — is Tor Browser / tor daemon running?"
    return result
