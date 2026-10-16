# 🕵️‍♂️ GhostTrace v4 — Digital Footprint Hunter & Account Eraser

## 💡 What is this in simple words?

Over the years, you've probably created accounts on dozens of websites—old forums, games, social networks, and shopping apps you forgot about.

**GhostTrace** is like a private investigator for your online identity:
1. You give it your **email address, username, or phone number**.
2. It quietly checks **180+ websites** (Instagram, GitHub, Reddit, Spotify, old forums, leak databases) to see where your accounts exist.
3. It displays all found accounts on a clean visual dashboard.
4. It helps you generate ready-to-send **GDPR deletion request emails** asking those companies to permanently delete your data and account.

Everything runs on your computer. Your search history is stored in a private local database (`ghosttrace.db`), never sent to any external server.

---

## 📁 What does each file & script do?

| File / Folder | What it actually does |
| :--- | :--- |
| **`app.py`** | **The main web app!** Starts the interactive browser dashboard at `http://127.0.0.1:5000`. Run this if you want the visual interface. |
| **`scan_cli.py`** | **Terminal Scanner**: Lets you run a scan directly from the command line without opening a browser (e.g. `python scan_cli.py --email user@example.com`). |
| **`checker.py`** | The underlying scanning engine that checks whether an email or username exists on target websites. |
| **`checkers/`** | Specialized plugins: |
| ├── `surface.py` | Checks 53 popular mainstream websites (social media, dev tools, e-commerce). |
| ├── `username.py` | Checks 114 websites for a specific username. |
| ├── `deep.py` | Checks public breach databases, certificate logs, and paste websites. |
| ├── `phone.py` | Checks public caller ID and phone registries. |
| ├── `image.py` | Extracts hidden metadata (EXIF) from photos and searches for image re-use. |
| └── `tor_proxy.py` | Allows routing searches through the Tor network for anonymous scanning. |
| **`db.py` & `ghosttrace.db`** | Local SQLite database that saves your scan results so you can see changes over time. |
| **`ai/`** | Optional AI helper that analyzes your exposure risk and suggests which accounts to delete first. |
| **`templates/`** | The HTML pages for the web dashboard. |

---

## 🚀 How to Run It (Step-by-Step)

### Option 1: Web Dashboard (Recommended)

1. Open PowerShell and go to this directory:
   ```powershell
   cd c:\Users\user\Desktop\projects\ghosttrace_delete_from_internet
   ```
2. Activate the virtual environment:
   ```powershell
   venv\Scripts\activate
   ```
   *(If dependencies aren't installed yet, run `pip install -r requirements.txt`)*
3. Start the server:
   ```powershell
   python app.py
   ```
4. Open your browser and go to:  
   👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

5. Type an email or username into the search box and click **Scan**. Watch accounts pop up live!

---

### Option 2: Quick Command-Line Scan (Terminal Only)

Want a fast scan without opening a web browser?
```powershell
python scan_cli.py --email yourname@gmail.com
```
or:
```powershell
python scan_cli.py --username yourhandle
```
It prints a list of all sites where that handle exists right in your terminal.

---

## Technical Limitations

- **Endpoint Rate Limiting**: High-volume enumeration without Tor or proxy pools triggers HTTP 429 (Too Many Requests) or Cloudflare WAF bot-challenge intercepts on rate-sensitive targets.
- **Wildcard Response Collisions**: Certain legacy web services return generic HTTP 200 pages for non-existent profiles, requiring regex heuristic validation that may produce occasional false positives.
- **Manual Deletion Dispatch**: Deletion notices are generated as compliant legal drafts (GDPR Article 17 / CCPA); execution requires manual dispatch from the user's mail client due to anti-spam mail server policies.

---

## Future Roadmap

- [ ] **Playwright Headless Evaluator**: Add an optional headless browser runtime to render dynamic SPA account registration flows with automated CAPTCHA handling.
- [ ] **OAuth Grant Auditor**: Integrate direct read-only OAuth consent token enumeration for Google, GitHub, and Apple ID single sign-ons.
- [ ] **IMAP Deletion Tracking Daemon**: Implement an inbound mail monitor to automatically parse, track, and confirm vendor deletion compliance receipts.
- [ ] **Cryptographic Compliance Log**: Export digitally signed and timestamped audit bundles documenting identified public records.

