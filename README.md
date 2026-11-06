# GhostTrace: Automated Digital Footprint Reconnaissance & GDPR Compliance Engine

A zero-cloud, privacy-preserving OSINT reconnaissance tool that scans across 180+ web services to identify public digital exposure and automates legal data erasure requests under GDPR Article 17 and CCPA.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Compliance: GDPR Art. 17 / CCPA](https://img.shields.io/badge/Compliance-GDPR%20Art.%2017%20%7C%20CCPA-green.svg)](docs/)
[![Architecture: Local / Zero-Cloud](https://img.shields.io/badge/Privacy-Zero--Cloud%20Local%20Only-brightgreen.svg)](db.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

Over years of internet use, user identifiers (email addresses, handles, phone numbers) are replicated across hundreds of online platforms, forums, and legacy databases—often without ongoing user awareness.

**GhostTrace** is an automated identity discovery and compliance utility that:
1. **Enumerates Identity Exposure:** Evaluates targets against 180+ service endpoints (mainstream social platforms, developer infrastructure, public breach registries, public certificate transparency logs).
2. **Local Security Perimeter:** Runs entirely on the user's host with zero telemetry and zero third-party cloud data transmission; results are persisted into an encrypted local SQLite database (`ghosttrace.db`).
3. **Automates Regulatory Remediation:** Synthesizes legally compliant erasure notices under **GDPR Article 17 ("Right to Erasure")** and **CCPA ("Right to Delete")**, pre-addressed to registered Data Protection Officers (DPO) and legal compliance desks.

---

## Architectural Components

```
ghosttrace/
├── app.py              # Flask-based local operational dashboard & interactive console
├── scan_cli.py         # Headless CLI scanner for programmatic CI/terminal execution
├── checker.py          # Asynchronous HTTP orchestration engine & response heuristic evaluator
├── checkers/
│   ├── surface.py      # Mainstream SaaS & social identity enumeration (53 endpoints)
│   ├── username.py     # Cross-platform handle discovery across 114 registries
│   ├── deep.py         # Public breach databases, certificate logs, and paste caches
│   ├── phone.py        # Public telecommunication routing and registry checks
│   ├── image.py        # Reverse visual signature indexing and EXIF metadata extractor
│   └── tor_proxy.py    # SOCKS5 routing proxy for anonymous, anti-attribution scanning
└── db.py               # Local SQLite abstraction layer with historical scan auditing
```

---

## Deployment & Execution

### 1. Web Telemetry Console
Launch the local web dashboard for interactive scanning and GDPR notice generation:

```bash
# Install dependencies
pip install -r requirements.txt

# Start local server (bound to localhost only)
python app.py
```
Navigate to `http://127.0.0.1:5000` to access the scanning console.

### 2. Headless CLI Reconnaissance
For automated terminal workflows or server environments:

```bash
# Target enumeration by email address
python scan_cli.py --email analyst@example.com

# Target enumeration by handle
python scan_cli.py --username target_handle
```

---

## Security, Anonymity & Compliance Safeguards

* **Tor SOCKS5 Transport Layer:** Integrated proxy dispatch (`tor_proxy.py`) allows outbound probe traffic to be routed through the Tor onion routing network, preventing source IP exposure and local network logging.
* **Passive & Non-Intrusive Probing:** Scans leverage standard public protocol endpoints (registration verification APIs, public profile lookups, password-reset presence checks) without conducting unauthorized authentication attempts or credential testing.
* **Legal Drafting Standards:** Generated Article 17 notices cite relevant statutory provisions, specific data categories identified during scanning, and statutory 30-day compliance deadlines.
