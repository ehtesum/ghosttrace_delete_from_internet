"""
Domain OSINT scanner.
Checks: DNS records, SSL certificate transparency (crt.sh), HTTP fingerprint,
WHOIS registration (via RDAP), and data broker search links.
All requests originate from your machine — no third-party relay.
"""
import json
import re
import socket
import time
from typing import Optional

import requests


class DomainScanner:
    TIMEOUT = 8

    def __init__(self, domain: str, session: requests.Session):
        self.domain  = domain.lower().strip()
        self.session = session
        self.results = []

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

    def _get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.TIMEOUT, **kwargs)
        except Exception:
            return None

    # ── DNS records ──────────────────────────────────────────────────────────────
    def _check_dns(self):
        records = {}
        # A record
        try:
            ip = socket.gethostbyname(self.domain)
            records["A"] = ip
        except Exception:
            records["A"] = "unresolvable"

        # MX via Google DoH (DNS-over-HTTPS — no local resolver dependency)
        for rtype in ("MX", "TXT", "NS"):
            try:
                r = self._get(
                    "https://dns.google/resolve",
                    params={"name": self.domain, "type": rtype},
                )
                if r and r.status_code == 200:
                    data = r.json()
                    answers = data.get("Answer", [])
                    records[rtype] = [a.get("data", "") for a in answers[:5]]
            except Exception:
                pass

        if records.get("A") and records["A"] != "unresolvable":
            detail = f"Resolves to {records['A']}"
            if records.get("MX"):
                detail += f" · MX: {records['MX'][0][:50]}"
            status = "found"
        else:
            detail = "Domain does not resolve"
            status = "not_found"

        self._add(
            "dns", "DNS Records", status, detail, "",
            [{"field": k, "value": str(v)} for k, v in records.items() if v],
        )
        return records

    # ── RDAP / WHOIS ─────────────────────────────────────────────────────────────
    def _check_whois(self):
        tld = self.domain.split(".")[-1]
        rdap_url = f"https://rdap.org/domain/{self.domain}"
        r = self._get(rdap_url)
        if r and r.status_code == 200:
            try:
                d = r.json()
                registrar = ""
                created   = ""
                expires   = ""
                for ent in d.get("entities", []):
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [None, []])[1]
                        for field in vcard:
                            if field[0] == "fn":
                                registrar = field[3]
                                break
                for ev in d.get("events", []):
                    if ev.get("eventAction") == "registration":
                        created = ev.get("eventDate", "")[:10]
                    if ev.get("eventAction") == "expiration":
                        expires = ev.get("eventDate", "")[:10]
                detail = f"Registrar: {registrar or '?'}"
                if created: detail += f" · Created: {created}"
                if expires: detail += f" · Expires: {expires}"
                self._add("whois", "WHOIS / RDAP", "found", detail, rdap_url, [
                    {"field": "Registrar", "value": registrar or "?"},
                    {"field": "Created",   "value": created or "?"},
                    {"field": "Expires",   "value": expires or "?"},
                    {"field": "TLD",       "value": tld},
                ])
                return
            except Exception:
                pass
        self._add("whois", "WHOIS / RDAP", "unknown", "RDAP lookup failed — try whois.domaintools.com", rdap_url)

    # ── Certificate transparency (crt.sh) ────────────────────────────────────────
    def _check_certs(self):
        r = self._get(
            "https://crt.sh/",
            params={"q": f"%.{self.domain}", "output": "json"},
        )
        if not r or r.status_code != 200:
            self._add("certs", "SSL Certificates (crt.sh)", "unknown", "crt.sh lookup failed")
            return

        try:
            entries = r.json()
        except Exception:
            self._add("certs", "SSL Certificates (crt.sh)", "unknown", "Could not parse crt.sh response")
            return

        seen = set()
        subdomains = []
        emails_found = set()
        for e in entries:
            name = e.get("name_value", "")
            for n in name.splitlines():
                n = n.strip().lstrip("*.")
                if n and n not in seen and n.endswith(self.domain):
                    seen.add(n)
                    subdomains.append(n)
            # Check if any cert was issued to an email
            issuer = e.get("issuer_name", "")
            if "@" in issuer:
                match = re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}', issuer)
                if match:
                    emails_found.add(match.group(0))

        count = len(subdomains)
        if count:
            detail = f"{count} subdomain(s) found via SSL transparency logs"
            data = [{"field": "subdomain", "value": s} for s in sorted(subdomains)[:30]]
            if emails_found:
                for em in emails_found:
                    data.append({"field": "email_in_cert", "value": em})
            self._add("certs", "SSL Certificates (crt.sh)", "found", detail,
                      f"https://crt.sh/?q=%.{self.domain}", data)
        else:
            self._add("certs", "SSL Certificates (crt.sh)", "not_found",
                      "No certificates found in transparency logs",
                      f"https://crt.sh/?q=%.{self.domain}")

    # ── HTTP fingerprint ─────────────────────────────────────────────────────────
    def _check_http(self):
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.domain}"
            try:
                r = self.session.get(url, timeout=8, allow_redirects=True)
                server  = r.headers.get("Server", "")
                powered = r.headers.get("X-Powered-By", "")
                cms     = ""
                body    = r.text[:4000].lower()
                if "wp-content" in body or "wordpress" in body:
                    cms = "WordPress"
                elif "shopify" in body:
                    cms = "Shopify"
                elif "wix.com" in body:
                    cms = "Wix"
                elif "squarespace" in body:
                    cms = "Squarespace"
                elif "webflow" in body:
                    cms = "Webflow"
                elif "ghost.io" in body or "ghost-theme" in body:
                    cms = "Ghost"
                parts = []
                if server:   parts.append(f"Server: {server}")
                if powered:  parts.append(f"Powered: {powered}")
                if cms:      parts.append(f"CMS: {cms}")
                detail = " · ".join(parts) or f"HTTP {r.status_code}"
                self._add("http", "HTTP Fingerprint", "found", detail, url, [
                    {"field": "Status",     "value": str(r.status_code)},
                    {"field": "Server",     "value": server or "hidden"},
                    {"field": "X-Powered-By", "value": powered or "hidden"},
                    {"field": "CMS",        "value": cms or "unknown"},
                    {"field": "Final URL",  "value": r.url[:120]},
                ])
                return
            except Exception:
                continue
        self._add("http", "HTTP Fingerprint", "not_found", "Domain did not respond to HTTP/HTTPS")

    # ── Search / OSINT links ─────────────────────────────────────────────────────
    def _check_osint_links(self):
        links = [
            {"name": "Google",          "url": f"https://www.google.com/search?q=site:{self.domain}"},
            {"name": "Google (emails)", "url": f"https://www.google.com/search?q=site:{self.domain}+%22%40{self.domain}%22"},
            {"name": "Shodan",          "url": f"https://www.shodan.io/search?query={self.domain}"},
            {"name": "BuiltWith",       "url": f"https://builtwith.com/{self.domain}"},
            {"name": "SecurityTrails",  "url": f"https://securitytrails.com/domain/{self.domain}/dns"},
            {"name": "VirusTotal",      "url": f"https://www.virustotal.com/gui/domain/{self.domain}"},
            {"name": "URLScan.io",      "url": f"https://urlscan.io/search/#domain:{self.domain}"},
            {"name": "ViewDNS",         "url": f"https://viewdns.info/whois/?domain={self.domain}"},
        ]
        self._add("domain_osint", "OSINT Search Links", "manual",
                  "Use these tools to investigate the domain further.", "", links)

    # ── main ─────────────────────────────────────────────────────────────────────
    def scan(self) -> dict:
        self._check_dns()
        self._check_whois()
        self._check_certs()
        self._check_http()
        self._check_osint_links()
        return {
            "domain":  self.domain,
            "results": self.results,
        }
