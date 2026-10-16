"""
Phone number OSINT scanner.
Runs entirely from your machine — no credentials required.
Paid-API checks are stubbed with manual OSINT guidance.
"""
import re
import time

import requests

# ── Country code table (top 50 dialling codes) ────────────────────────────────
_COUNTRY_CODES = {
    "1":   ("United States / Canada", "NA"),
    "7":   ("Russia / Kazakhstan",    "EU"),
    "20":  ("Egypt",                  "AF"),
    "27":  ("South Africa",           "AF"),
    "30":  ("Greece",                 "EU"),
    "31":  ("Netherlands",            "EU"),
    "32":  ("Belgium",                "EU"),
    "33":  ("France",                 "EU"),
    "34":  ("Spain",                  "EU"),
    "36":  ("Hungary",                "EU"),
    "39":  ("Italy",                  "EU"),
    "40":  ("Romania",                "EU"),
    "41":  ("Switzerland",            "EU"),
    "43":  ("Austria",                "EU"),
    "44":  ("United Kingdom",         "EU"),
    "45":  ("Denmark",                "EU"),
    "46":  ("Sweden",                 "EU"),
    "47":  ("Norway",                 "EU"),
    "48":  ("Poland",                 "EU"),
    "49":  ("Germany",                "EU"),
    "51":  ("Peru",                   "SA"),
    "52":  ("Mexico",                 "NA"),
    "54":  ("Argentina",              "SA"),
    "55":  ("Brazil",                 "SA"),
    "56":  ("Chile",                  "SA"),
    "57":  ("Colombia",               "SA"),
    "58":  ("Venezuela",              "SA"),
    "60":  ("Malaysia",               "AS"),
    "61":  ("Australia",              "OC"),
    "62":  ("Indonesia",              "AS"),
    "63":  ("Philippines",            "AS"),
    "64":  ("New Zealand",            "OC"),
    "65":  ("Singapore",              "AS"),
    "66":  ("Thailand",               "AS"),
    "81":  ("Japan",                  "AS"),
    "82":  ("South Korea",            "AS"),
    "84":  ("Vietnam",                "AS"),
    "86":  ("China",                  "AS"),
    "90":  ("Turkey",                 "EU"),
    "91":  ("India",                  "AS"),
    "92":  ("Pakistan",               "AS"),
    "93":  ("Afghanistan",            "AS"),
    "94":  ("Sri Lanka",              "AS"),
    "95":  ("Myanmar",                "AS"),
    "98":  ("Iran",                   "AS"),
    "212": ("Morocco",                "AF"),
    "213": ("Algeria",                "AF"),
    "216": ("Tunisia",                "AF"),
    "218": ("Libya",                  "AF"),
    "220": ("Gambia",                 "AF"),
    "234": ("Nigeria",                "AF"),
    "254": ("Kenya",                  "AF"),
    "255": ("Tanzania",               "AF"),
    "256": ("Uganda",                 "AF"),
    "260": ("Zambia",                 "AF"),
    "263": ("Zimbabwe",               "AF"),
    "966": ("Saudi Arabia",           "AS"),
    "971": ("United Arab Emirates",   "AS"),
    "972": ("Israel",                 "AS"),
    "974": ("Qatar",                  "AS"),
    "977": ("Nepal",                  "AS"),
    "992": ("Tajikistan",             "AS"),
    "998": ("Uzbekistan",             "AS"),
}


def _parse_phone(raw: str) -> dict:
    """Strip and identify the country from a phone number string."""
    digits = re.sub(r"[^\d+]", "", raw)
    if not digits.startswith("+"):
        digits = "+" + digits.lstrip("0")

    # Remove the +
    num = digits[1:]

    country = "Unknown"
    cc = ""
    # Try 3-digit, 2-digit, 1-digit prefix
    for length in (3, 2, 1):
        candidate = num[:length]
        if candidate in _COUNTRY_CODES:
            country, _ = _COUNTRY_CODES[candidate]
            cc = candidate
            break

    return {
        "raw":       raw,
        "e164":      digits,
        "local":     num[len(cc):] if cc else num,
        "cc":        cc,
        "country":   country,
        "digits":    num,
        "is_valid":  len(num) >= 7 and len(num) <= 15,
    }


class PhoneScanner:
    TIMEOUT = 8

    def __init__(self, raw_number: str, session: requests.Session):
        self.parsed  = _parse_phone(raw_number)
        self.session = session
        self.results = []

    # ── helpers ──────────────────────────────────────────────────────────────────
    def _add(self, check_id: str, name: str, status: str, detail: str,
             url: str = "", data: list = None):
        self.results.append({
            "id":     check_id,
            "name":   name,
            "status": status,
            "detail": detail,
            "url":    url,
            "data":   data or [],
        })

    def _get(self, url: str, **kwargs):
        try:
            r = self.session.get(url, timeout=self.TIMEOUT, **kwargs)
            return r
        except Exception:
            return None

    # ── individual checks ────────────────────────────────────────────────────────
    def _check_telegram(self):
        """Telegram allows resolving phone → username if public profile set."""
        p = self.parsed
        self._add(
            "telegram_phone", "Telegram (manual)",
            "manual",
            "Open Telegram → New Message → search this number to see if it has an account.",
            "https://t.me",
        )

    def _check_whatsapp(self):
        """WhatsApp click-to-chat link — non-null means account may exist."""
        p = self.parsed
        wa_url = f"https://api.whatsapp.com/send?phone={p['digits']}"
        r = self._get(wa_url, allow_redirects=True)
        if r and r.status_code == 200 and "wa.me" in r.url:
            status = "found"
            detail = "WhatsApp profile may exist — click to verify."
        else:
            status = "unknown"
            detail = "Could not confirm WhatsApp registration (rate-limited or private)."
        self._add("whatsapp", "WhatsApp", status, detail, wa_url)

    def _check_truecaller(self):
        self._add(
            "truecaller", "Truecaller (manual)",
            "manual",
            f"Search {self.parsed['e164']} on Truecaller to find the registered name.",
            f"https://www.truecaller.com/search/us/{self.parsed['digits']}",
        )

    def _check_numverify(self):
        """Free tier with no key returns limited info."""
        p = self.parsed
        url = f"http://apilayer.net/api/validate?number={p['digits']}&format=1"
        r = self._get(url)
        if r and r.status_code == 200:
            try:
                d = r.json()
                if d.get("valid"):
                    self._add(
                        "numverify", "NumVerify",
                        "found",
                        f"Valid: {d.get('carrier','?')} | {d.get('line_type','?')} | {d.get('location','?')}",
                        "",
                        [{"field": k, "value": str(v)} for k, v in d.items() if v and k not in ("success","")]
                    )
                    return
            except Exception:
                pass
        self._add("numverify", "NumVerify", "unknown", "API unavailable (no key)")

    def _check_data_brokers(self):
        """Static data broker opt-out links for phone numbers."""
        brokers = [
            {"name": "Spokeo",       "url": f"https://www.spokeo.com/search?q={self.parsed['digits']}"},
            {"name": "WhitePages",   "url": f"https://www.whitepages.com/phone/{self.parsed['digits']}"},
            {"name": "AnyWho",       "url": f"https://www.anywho.com/tel/{self.parsed['digits']}"},
            {"name": "NumberGuru",   "url": f"https://www.numberguru.com/{self.parsed['digits']}"},
            {"name": "CallerSmart",  "url": f"https://www.callersmart.com/phone/{self.parsed['digits']}"},
            {"name": "Intelius",     "url": f"https://www.intelius.com/results.php?ReportType=phone&search={self.parsed['digits']}"},
        ]
        self._add(
            "phone_brokers", "Phone Data Brokers",
            "found",
            f"Your number may appear in {len(brokers)} people-search sites. Check each and request removal.",
            "",
            brokers,
        )

    def _check_osint_links(self):
        """Generate OSINT search links for manual investigation."""
        num = self.parsed["digits"]
        links = [
            {"name": "Google Search",   "url": f"https://www.google.com/search?q=%22{num}%22"},
            {"name": "Google (formatted)", "url": f"https://www.google.com/search?q=%22{self.parsed['e164']}%22"},
            {"name": "Pastebin Search", "url": f"https://www.google.com/search?q=site:pastebin.com+%22{num}%22"},
            {"name": "GitHub Search",   "url": f"https://github.com/search?q=%22{num}%22&type=code"},
        ]
        self._add(
            "phone_osint", "OSINT Search Links",
            "manual",
            "Use these links to search for your number on the public web.",
            "",
            links,
        )

    # ── main ─────────────────────────────────────────────────────────────────────
    def scan(self) -> dict:
        p = self.parsed
        if not p["is_valid"]:
            return {
                "parsed":  p,
                "valid":   False,
                "error":   "Invalid phone number — must be 7–15 digits with country code (e.g. +1 555 000 0000)",
                "results": [],
            }

        self._check_truecaller()
        self._check_whatsapp()
        self._check_telegram()
        self._check_numverify()
        self._check_data_brokers()
        self._check_osint_links()

        return {
            "parsed":  p,
            "valid":   True,
            "results": self.results,
        }
