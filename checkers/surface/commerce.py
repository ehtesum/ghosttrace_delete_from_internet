from checkers.base import BaseChecker


class EbayChecker(BaseChecker):
    ID, NAME = "ebay", "eBay"
    PRIVACY, CATEGORY = "direct", "commerce"
    DELETE_URL = "https://www.ebay.com/help/account/closing-account"

    def check(self):
        r = self._post(
            "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn",
            data={"userid": self.email, "pass": "GhostProbe9z!"},
            headers={"Referer": "https://signin.ebay.com/"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and "incorrect" in text:
            return self.found("Account found (wrong password)")
        if "no account" in text or "can't find" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine")


class PayPalChecker(BaseChecker):
    ID, NAME = "paypal", "PayPal"
    PRIVACY, CATEGORY = "direct", "commerce"
    DELETE_URL = "https://www.paypal.com/myaccount/settings/"

    def check(self):
        r = self._post(
            "https://www.paypal.com/authflow/entry/",
            json={"email": self.email},
            headers={"Content-Type": "application/json", "Origin": "https://www.paypal.com"},
        )
        if not r:
            return self.error("Connection failed")
        try:
            d = r.json()
            if d.get("data", {}).get("accountStatus"):
                return self.found("PayPal account found")
            errors = str(d).lower()
            if "not found" in errors or "no account" in errors:
                return self.not_found("No account found")
        except Exception:
            pass
        return self.unknown(f"HTTP {r.status_code}")


class EtsyChecker(BaseChecker):
    ID, NAME = "etsy", "Etsy"
    PRIVACY, CATEGORY = "direct", "commerce"
    DELETE_URL = "https://help.etsy.com/hc/en-us/articles/115015569347"

    def check(self):
        r = self._post(
            "https://www.etsy.com/api/v3/ajax/member/authenticate",
            json={"email": self.email, "password": "GhostProbe9z!"},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            return self.error("Connection failed")
        text = r.text.lower()
        if "password" in text and ("wrong" in text or "incorrect" in text):
            return self.found("Account found (wrong password)")
        if "no account" in text or "not found" in text:
            return self.not_found("No account found")
        return self.unknown("Could not determine")
