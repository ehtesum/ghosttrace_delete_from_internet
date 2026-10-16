from checkers.base import BaseChecker


class CrtShChecker(BaseChecker):
    ID, NAME = "crt_sh", "Certificate Transparency (crt.sh)"
    PRIVACY, CATEGORY = "api", "infrastructure"
    LAYER = "deep"
    DELETE_URL = ""

    def check(self):
        r = self._get("https://crt.sh/", params={"q": self.email, "output": "json"})
        if not r:
            return self.error("Connection failed")
        if r.status_code == 200:
            try:
                certs = r.json()
                if certs:
                    domains = list({c.get("common_name", "") for c in certs if c.get("common_name")})[:10]
                    return self.found(
                        f"{len(certs)} SSL cert(s) found  |  Domains: {', '.join(domains[:5])}",
                        data=domains,
                    )
                return self.not_found("No certificates linked to this email")
            except Exception:
                pass
        return self.unknown(f"HTTP {r.status_code}")
