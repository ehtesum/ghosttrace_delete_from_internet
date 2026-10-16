import asyncio
import json
import logging
import queue
import random
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from flask_cors import CORS

from checkers import DEEP_CHECKERS, SURFACE_CHECKERS
import db as _db

# new orchestrator import (uses ghosttrace core manager)
try:
    from ghosttrace.core.manager import AsyncScannerManager
    from ghosttrace.core.proxies import ProxyConfig
except Exception:
    AsyncScannerManager = None
    ProxyConfig = None

# NOTE: removed logging.disable(logging.CRITICAL) — BUG-014
# Silencing all logging hides real errors in production.
logging.basicConfig(level=logging.WARNING)

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5000", "http://localhost:5000"])

MAX_WORKERS = 16

_db.init_db()

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]


def _session(use_tor: bool = False) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if use_tor:
        try:
            from checkers.tor_proxy import TOR_SOCKS
            s.proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
        except ImportError:
            pass
    return s


@app.after_request
def _privacy(response: Response) -> Response:
    response.headers.pop("Server", None)
    response.headers["Cache-Control"] = "no-store, no-cache, private"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route('/api/correlate', methods=['POST'])
def correlate():
    """Run a comprehensive correlation scan over multiple input tokens.

    Expects JSON: {"inputs": [{"type":"email","value":"..."}, ...], "include_adult":bool, "include_betting":bool}
    Streams Server-Sent Events (SSE) with messages produced by AsyncScannerManager.orchestrate_entities().
    """
    if AsyncScannerManager is None:
        return jsonify({'error': 'correlator not available'}), 500

    data = request.get_json(silent=True) or {}
    inputs = data.get('inputs') or []
    include_adult = bool(data.get('include_adult'))
    include_betting = bool(data.get('include_betting'))

    # build include/exclude tags
    include_tags = []
    exclude_tags = []
    if include_adult:
        include_tags.append('adult')
    else:
        exclude_tags.append('adult')
    if include_betting:
        include_tags.append('betting')
    else:
        exclude_tags.append('betting')

    use_tor = bool(data.get('tor')) or request.args.get('tor', '0') == '1'
    proxy_config = ProxyConfig(use_tor=use_tor) if ProxyConfig else None
    cfg = {'include_tags': include_tags or None, 'exclude_tags': exclude_tags or None}
    if proxy_config:
        cfg['proxy'] = proxy_config

    mgr = AsyncScannerManager()

    q = queue.Queue()
    stop = threading.Event()  # FIX BUG-13: thread leak — Event lets the SSE generator signal the runner to abort

    def _runner(stop_event: threading.Event):
        try:
            async def _inner():
                async for ev in mgr.orchestrate_entities(
                    inputs,
                    mode='comprehensive',
                    config=cfg,
                ):
                    if stop_event.is_set():
                        return
                    q.put(ev)
            asyncio.run(_inner())
        except Exception as exc:
            q.put({'type': 'error', 'details': str(exc)})
        finally:
            q.put(None)

    threading.Thread(target=_runner, args=(stop,), daemon=True).start()

    def generate():
        try:
            while True:
                try:
                    item = q.get(timeout=120)
                except queue.Empty:
                    yield f"data: {json.dumps({'type':'error','details':'scan timed out'})}\n\n"
                    break
                if item is None:
                    yield f"data: {json.dumps({'type':'done'})}\n\n"
                    break
                try:
                    yield f"data: {json.dumps(item)}\n\n"
                except Exception:
                    yield f"data: {json.dumps({'type':'error','details':'serialization error'})}\n\n"
        except GeneratorExit:
            stop.set()  # FIX BUG-13: browser tab closed raises GeneratorExit; set() propagates cancellation to daemon thread

    return Response(stream_with_context(generate()), mimetype='text/event-stream', headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route('/api/tor-status')
def tor_status():
    try:
        from checkers.tor_proxy import is_tor_available
        return jsonify(is_tor_available())
    except Exception as exc:
        return jsonify({"available": False, "message": str(exc)}), 500


# ── Email scan (SSE) ──────────────────────────────────────────────────────────

@app.route("/api/scan")
def scan():
    """Stream surface or deep scan results as SSE — parallel execution."""
    email    = request.args.get("email", "").strip().lower()
    layer    = request.args.get("layer", "surface")
    hibp_key = request.args.get("hibp_key", "").strip()
    emailrep_key = request.args.get("emailrep_key", "").strip()
    use_tor  = request.args.get("tor", "0") == "1"

    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "Invalid email address"}), 400

    checkers = SURFACE_CHECKERS if layer == "surface" else DEEP_CHECKERS

    def _run(Cls, session):
        try:
            return Cls(email, session, hibp_key=hibp_key, emailrep_key=emailrep_key).check()
        except Exception as exc:
            return {
                "id": Cls.ID, "name": Cls.NAME,
                "status": "error", "details": str(exc)[:100],
                "privacy": Cls.PRIVACY, "category": Cls.CATEGORY,
                "layer": Cls.LAYER, "delete_url": Cls.DELETE_URL, "data": [],
            }

    def generate():
        session   = _session(use_tor=use_tor)
        total     = len(checkers)
        completed = 0
        lock      = threading.Lock()

        yield f"data: {json.dumps({'type': 'progress', 'current': 0, 'total': total, 'checking': 'Starting parallel scan…'})}\n\n"

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(_run, Cls, session): Cls for Cls in checkers}
            for future in as_completed(futures):
                Cls    = futures[future]
                result = future.result()
                with lock:
                    completed += 1
                    c = completed
                yield f"data: {json.dumps({'type': 'progress', 'current': c, 'total': total, 'checking': Cls.NAME})}\n\n"
                yield f"data: {json.dumps({'type': 'result', **result})}\n\n"

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Holehe scan (SSE) ────────────────────────────────────────────────────────

@app.route("/api/holehe-scan")
def holehe_scan_route():
    """Run holehe across 121 platforms and stream results as SSE."""
    email = request.args.get("email", "").strip().lower()
    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "Invalid email address"}), 400

    rq = queue.Queue()

    def _run():
        try:
            import asyncio
            import httpx
            import holehe.core as _holehe

            async def _inner():
                mods     = _holehe.import_submodules("holehe.modules")
                websites = _holehe.get_functions(mods)
                rq.put({"_total": len(websites)})
                async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                    for website in websites:
                        out = []
                        try:
                            await website(email, client, out)
                        except Exception:
                            pass
                        rq.put({"_raw": out[-1] if out else {
                            "name": website.__name__,
                            "domain": website.__name__ + ".com",
                            "exists": None, "rateLimit": False,
                        }})

            asyncio.run(_inner())
        except Exception as exc:
            rq.put({"_error": str(exc)[:200]})
        finally:
            rq.put(None)

    threading.Thread(target=_run, daemon=True).start()

    def generate():
        total = None
        done  = 0
        while True:
            try:
                item = rq.get(timeout=180)  # FIX BUG-25: holehe generator had no timeout; hung forever if any module blocked
            except queue.Empty:
                yield f"data: {json.dumps({'type':'error','details':'holehe scan timed out'})}\n\n"
                break
            if item is None:
                yield f"data: {json.dumps({'type':'done'})}\n\n"
                break
            if "_total" in item:
                total = item["_total"]
                # Emit the first progress event only after the real total is known
                yield f"data: {json.dumps({'type':'progress','current':0,'total':total,'checking':'Starting holehe…'})}\n\n"
                continue
            if "_error" in item:
                yield f"data: {json.dumps({'type':'error','details':item['_error']})}\n\n"
                continue

            raw    = item["_raw"]
            done  += 1
            name   = raw.get("name", "unknown")
            domain = raw.get("domain", name + ".com")
            exists = raw.get("exists")
            rl     = raw.get("rateLimit", False)

            if exists is True:
                status  = "found"
                details = "Account found"
                rec = raw.get("emailrecovery")
                ph  = raw.get("phoneNumber")
                if rec: details += f" | Recovery: {rec}"
                if ph:  details += f" | Phone: {ph}"
            elif exists is False:
                status  = "not_found"
                details = "No account found"
            elif rl:
                status  = "captcha_pending"
                details = "Bot-check / rate-limit — open site, solve CAPTCHA, then mark result"
            else:
                status  = "unknown"
                details = "Could not determine"

            result = {
                "id": "h_" + name,
                "name": name.replace("_", " ").title(),
                "status": status, "details": details,
                "privacy": "direct", "category": "holehe",
                "layer": "holehe",
                "delete_url": "https://" + domain,
                "data": [], "domain": domain,
            }
            yield f"data: {json.dumps({'type':'progress','current':done,'total':total,'checking':name})}\n\n"
            yield f"data: {json.dumps({'type':'result',**result})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Username hunt (SSE) ────────────────────────────────────────────────────────

@app.route("/api/username-scan")
def username_scan():
    """Stream username presence checks across 177 platforms."""
    username = request.args.get("username", "").strip()
    use_tor  = request.args.get("tor", "0") == "1"

    if not username or len(username) > 64:
        return jsonify({"error": "Username required (max 64 chars)"}), 400
    # FIX BUG-24: XSS — username was stored in SQLite and potentially rendered unsanitised by frontend; allow-list blocks injection chars
    if not re.match(r'^[\w.\-]{1,64}$', username):
        return jsonify({"error": "Invalid username: only letters, digits, '.', '_', '-' allowed"}), 400

    from checkers.username.sites import USERNAME_SITES

    def _check(site, session):
        url = site["url"].replace("{username}", username)
        # Small per-request jitter (50–250 ms) to avoid rate limits
        time.sleep(random.uniform(0.05, 0.25))
        try:
            r = session.get(url, timeout=10, allow_redirects=True)
            probe = site.get("probe", "status")
            if probe == "status":
                found = r.status_code == 200
            elif probe == "not_message":
                found = r.status_code == 200 and site.get("not_found_msg", "") not in r.text
            elif probe == "message":
                found = site.get("found_msg", "") in r.text
            else:
                found = r.status_code == 200
            return {
                "id":          site["id"],
                "name":        site["name"],
                "category":    site.get("category", "other"),
                "url":         url,
                "status":      "found" if found else "not_found",
                "profile_url": url if found else "",
                "confidence":  site.get("confidence", 70),
            }
        except Exception:
            return {
                "id":          site["id"],
                "name":        site["name"],
                "category":    site.get("category", "other"),
                "url":         url,
                "status":      "error",
                "profile_url": "",
                "confidence":  site.get("confidence", 70),
            }

    def generate():
        session   = _session(use_tor=use_tor)
        total     = len(USERNAME_SITES)
        completed = 0
        lock      = threading.Lock()
        results   = []

        yield f"data: {json.dumps({'type': 'progress', 'current': 0, 'total': total, 'checking': 'Starting username hunt…'})}\n\n"

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(_check, site, session): site for site in USERNAME_SITES}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                with lock:
                    completed += 1
                    c = completed
                yield f"data: {json.dumps({'type': 'progress', 'current': c, 'total': total, 'checking': result['name']})}\n\n"
                yield f"data: {json.dumps({'type': 'result', **result})}\n\n"

        try:
            _db.save_username_scan(username, results)
        except Exception:
            pass

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Phone OSINT ────────────────────────────────────────────────────────────────

@app.route("/api/phone-scan", methods=["POST"])
def phone_scan():
    data  = request.json or {}
    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"error": "Phone number required"}), 400

    from checkers.phone.lookup import PhoneScanner
    result = PhoneScanner(phone, _session()).scan()
    return jsonify(result)


# ── Domain OSINT ───────────────────────────────────────────────────────────────

@app.route("/api/domain-scan", methods=["POST"])
def domain_scan():
    """WHOIS, DNS records, certificate transparency, and HTTP fingerprint."""
    data   = request.json or {}
    domain = data.get("domain", "").strip().lower()
    if not domain or "." not in domain:
        return jsonify({"error": "Valid domain required (e.g. example.com)"}), 400
    # Strip protocol if accidentally included
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    from checkers.domain.lookup import DomainScanner
    result = DomainScanner(domain, _session()).scan()
    return jsonify(result)


# ── AI analysis (SSE) ─────────────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Stream Claude AI analysis as plain text."""
    data = request.json or {}
    key  = data.get("claude_key", "").strip()
    if not key:
        return jsonify({"error": "Claude API key required"}), 400

    from ai.analyst import AIAnalyst

    def generate():
        try:
            analyst = AIAnalyst(key)
            for chunk in analyst.stream(
                data.get("email", ""),
                data.get("surface", []),
                data.get("deep", []),
            ):
                yield chunk
        except Exception as exc:
            yield json.dumps({"error": str(exc)})

    return Response(
        stream_with_context(generate()),
        mimetype="text/plain",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Scan history ──────────────────────────────────────────────────────────────

@app.route("/api/history/save", methods=["POST"])
def history_save():
    data = request.json or {}
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"error": "email required"}), 400
    scan_id = _db.save_scan(
        email,
        data.get("surface", []),
        data.get("deep", []),
        data.get("ai"),
    )
    return jsonify({"ok": True, "id": scan_id})


@app.route("/api/history")
def history_list():
    email = request.args.get("email", "").strip()
    if email:
        return jsonify(_db.get_history(email))
    return jsonify({"emails": _db.get_emails(), "recent": _db.get_history(limit=20)})


@app.route("/api/history/<int:scan_id>")
def history_detail(scan_id):
    scan = _db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan)


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def history_delete(scan_id):
    _db.delete_scan(scan_id)
    return jsonify({"ok": True})


@app.route("/api/history/diff")
def history_diff():
    old_id = request.args.get("old", type=int)
    new_id = request.args.get("new", type=int)
    if not old_id or not new_id:
        return jsonify({"error": "old and new scan IDs required"}), 400
    return jsonify(_db.diff_scans(old_id, new_id))


@app.route("/api/username-history")
def username_history():
    return jsonify(_db.get_username_history())


# ── Image OSINT ────────────────────────────────────────────────────────────────

@app.route("/api/image-scan", methods=["POST"])
def image_scan():
    """Extract EXIF metadata from uploaded image — all processing is local."""
    if "image" not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    f = request.files["image"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    image_bytes = f.read()
    if len(image_bytes) > 20 * 1024 * 1024:
        return jsonify({"error": "Image too large (max 20 MB)"}), 400

    from checkers.image.metadata import extract_metadata
    from checkers.image.reverse_search import get_search_services

    metadata     = extract_metadata(image_bytes, f.filename)
    search_links = get_search_services()

    return jsonify({"metadata": metadata, "search_links": search_links})


@app.route("/api/image-yandex", methods=["POST"])
def image_yandex():
    """Proxy: upload image to Yandex reverse search — user-initiated only."""
    if "image" not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    image_bytes = request.files["image"].read()
    if len(image_bytes) > 10 * 1024 * 1024:
        return jsonify({"error": "Image too large for Yandex (max 10 MB)"}), 400

    from checkers.image.reverse_search import try_yandex_upload
    return jsonify(try_yandex_upload(image_bytes))


# ── Tor ───────────────────────────────────────────────────────────────────────

@app.route("/api/tor-check")
def tor_check():
    try:
        from checkers.tor_proxy import is_tor_available
        return jsonify(is_tor_available())
    except ImportError:
        return jsonify({"available": False, "message": "PySocks not installed — run: pip install PySocks"})


# ── Deletion guides ───────────────────────────────────────────────────────────

@app.route("/api/deletion-guide/<platform_id>")
def deletion_guide(platform_id):
    from checkers.deletion_guides import DELETION_GUIDES
    guide = DELETION_GUIDES.get(platform_id.lower())
    if not guide:
        return jsonify({"error": "No guide available", "platform_id": platform_id}), 404
    return jsonify(guide)


# ── GDPR email generator ──────────────────────────────────────────────────────

@app.route("/api/gdpr-email", methods=["POST"])
def gdpr_email():
    """Generate a GDPR/CCPA right-to-erasure email for a platform."""
    data        = request.json or {}
    # FIX BUG-23: CRLF injection — unsanitised platform/email values were interpolated directly into email headers
    platform    = data.get("platform", "").strip().replace("\r", "").replace("\n", "")
    platform_id = data.get("platform_id", "").strip().lower()
    email       = data.get("email", "").strip().replace("\r", "").replace("\n", "")
    if not platform or not email:
        return jsonify({"error": "platform and email required"}), 400

    from checkers.deletion_guides import DELETION_GUIDES
    guide      = DELETION_GUIDES.get(platform_id, {})
    dpo_email  = guide.get("data_request_email", "")
    delete_url = guide.get("delete_url", "")

    to_line = f"To: {dpo_email}" if dpo_email else "To: privacy@[platform].com"

    template = f"""Subject: Right to Erasure Request (GDPR Art. 17 / CCPA) — {email}
{to_line}

To Whom It May Concern at {platform},

I am writing to formally exercise my right to erasure ("right to be forgotten") under:
  • Article 17 of the General Data Protection Regulation (EU) 2016/679 (GDPR)
  • Section 1798.105 of the California Consumer Privacy Act (CCPA)
  • Other applicable privacy legislation

My account details:
  Email address: {email}
  Platform:      {platform}

I hereby request that you:
  1. Permanently delete all personal data you hold about me, including but not limited to:
     – Account credentials and profile information
     – Usage logs, activity history, and analytics data
     – Any data shared with third-party partners
  2. Confirm in writing within 30 days that the deletion has been completed.
  3. Provide details of any data retention obligations that prevent full deletion.

If you require identity verification before processing this request, please advise me of the
required documents and I will supply them promptly.

Failure to comply within the statutory timeframe (30 days under GDPR, 45 days under CCPA)
may result in a complaint to the relevant supervisory authority.

Yours sincerely,
[Your Name]
{email}
Date: {__import__('datetime').date.today().isoformat()}
"""
    return jsonify({"template": template, "platform": platform, "dpo_email": dpo_email, "delete_url": delete_url})


# ── Deletion confirmation ─────────────────────────────────────────────────────

@app.route("/api/deletion-confirm", methods=["POST"])
def deletion_confirm():
    data = request.json or {}
    email       = data.get("email", "").strip()
    platform_id = data.get("platform_id", "").strip()
    platform    = data.get("platform", "").strip()
    notes       = data.get("notes", "").strip()
    if not email or not platform_id:
        return jsonify({"error": "email and platform_id required"}), 400
    _db.confirm_deletion(email, platform_id, platform, notes)
    return jsonify({"ok": True})


@app.route("/api/deletion-confirm", methods=["DELETE"])
def deletion_unconfirm():
    data = request.json or {}
    email       = data.get("email", "").strip()
    platform_id = data.get("platform_id", "").strip()
    if not email or not platform_id:
        return jsonify({"error": "email and platform_id required"}), 400
    _db.unconfirm_deletion(email, platform_id)
    return jsonify({"ok": True})


@app.route("/api/deletions")
def deletions_list():
    email = request.args.get("email", "").strip()
    if not email:
        return jsonify({"error": "email required"}), 400
    return jsonify(_db.get_deletions(email))


# ── Deletion certificate ──────────────────────────────────────────────────────

@app.route("/api/deletion-certificate", methods=["POST"])
def deletion_certificate():
    """Generate a dated HTML deletion certificate showing cleanup progress."""
    from html import escape
    from datetime import datetime

    data      = request.json or {}
    email_raw = data.get("email", "unknown")
    found     = data.get("found", [])
    confirmed = set(data.get("confirmed", []))
    requested = set(data.get("requested", []))
    # FIX BUG-40: escape user-controlled fields — interpolated directly into text/html response
    email     = escape(email_raw)
    email_fn  = re.sub(r'[^\w.@-]', '_', email_raw)  # sanitised for Content-Disposition filename
    u_name    = escape(data.get("username", ""))

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # FIX BUG-41: client can send more confirmed IDs than found accounts, driving score above 100%
    score     = min(round(len(confirmed) / len(found) * 100), 100) if found else 0
    score_col = "#22c55e" if score >= 80 else "#f59e0b" if score >= 50 else "#ef4444"

    rows = ""
    for r in found:
        rid   = r.get("id", "")
        r_name = escape(r.get("name", ""))       # FIX BUG-40: platform name from POST body — must be escaped
        r_cat  = escape(r.get("category", ""))
        if rid in confirmed:
            rows += f'<tr><td>{r_name}</td><td>{r_cat}</td><td style="color:#22c55e;font-weight:600">✓ DELETED</td></tr>\n'
        elif rid in requested:
            rows += f'<tr><td>{r_name}</td><td>{r_cat}</td><td style="color:#f59e0b;font-weight:600">📤 REQUESTED</td></tr>\n'
        else:
            rows += f'<tr><td>{r_name}</td><td>{r_cat}</td><td style="color:#ef4444;font-weight:600">⚠ PENDING</td></tr>\n'

    cert = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>GhostTrace Deletion Certificate — {email}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:40px;line-height:1.6;max-width:800px;margin:0 auto}}
.cert-header{{text-align:center;margin-bottom:40px;padding:32px;background:linear-gradient(135deg,rgba(124,58,237,.12),rgba(167,139,250,.08));border:2px solid rgba(124,58,237,.3);border-radius:16px}}
.cert-title{{font-size:1.8rem;font-weight:700;color:#a78bfa;margin-bottom:6px}}
.cert-sub{{font-size:.9rem;color:#8b949e;margin-bottom:12px}}
.cert-email{{font-size:1.1rem;font-weight:600;color:#c9d1d9;margin:8px 0}}
.cert-date{{font-size:.82rem;color:#8b949e}}
.score{{font-size:3rem;font-weight:700;color:{score_col};margin:16px 0 4px}}
.score-lbl{{font-size:.82rem;color:#8b949e}}
.stats{{display:flex;gap:24px;justify-content:center;font-size:.85rem;margin-top:12px}}
h2{{color:#a78bfa;font-size:.9rem;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #30363d;padding-bottom:6px;margin:32px 0 14px}}
table{{width:100%;border-collapse:collapse;font-size:.86rem}}
th{{text-align:left;padding:8px 12px;background:#161b22;color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px}}
td{{padding:8px 12px;border-bottom:1px solid #21262d}}
.wm{{margin-top:40px;font-size:.72rem;color:#484f58;border-top:1px solid #21262d;padding-top:12px;text-align:center}}
</style>
</head>
<body>
<div class="cert-header">
  <div class="cert-title">👻 GhostTrace Privacy Certificate</div>
  <div class="cert-sub">Digital Footprint Removal Record</div>
  <div class="cert-email">{email}</div>
  {f'<div class="cert-email" style="font-size:.9rem;color:#8b949e">@{u_name}</div>' if u_name else ''}
  <div class="cert-date">Generated: {generated}</div>
  <div class="score">{score}%</div>
  <div class="score-lbl">Cleanup Score</div>
  <div class="stats">
    <span style="color:#ef4444">🔴 {len(found)} found</span>
    <span style="color:#f59e0b">📤 {len(requested - confirmed)} requested</span>
    <span style="color:#22c55e">✓ {len(confirmed)} confirmed deleted</span>
  </div>
</div>
<h2>Account Status</h2>
<table>
<tr><th>Platform</th><th>Category</th><th>Status</th></tr>
{rows}
</table>
<div class="wm">GhostTrace v4 — Local OSINT scanner · Generated {generated} · No data leaves localhost<br>This certificate is self-generated. Keep copies of all deletion confirmation emails received.</div>
</body>
</html>"""

    return Response(
        cert,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="ghosttrace-cert-{email_fn}-{datetime.now().strftime("%Y%m%d")}.html"'},
    )


# ── HTML report export ────────────────────────────────────────────────────────

@app.route("/api/export-html", methods=["POST"])
def export_html():
    """Generate a self-contained HTML report of scan results."""
    data    = request.json or {}
    from html import escape as _esc
    email   = _esc(data.get("email", "unknown"))
    surface = data.get("surface", [])
    deep    = data.get("deep", [])
    ai      = data.get("ai")
    u_name  = _esc(data.get("username", ""))
    u_res   = data.get("usernameResults", [])

    from datetime import datetime
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    found_count = sum(
        1 for r in (surface or []) + (deep or [])
        if isinstance(r, dict) and r.get("status") == "found"
    )

    def status_color(s):
        return {"found": "#ef4444", "not_found": "#22c55e", "error": "#6b7280"}.get(s, "#6b7280")

    def rows(results):
        html = ""
        for r in results:
            col = status_color(r.get("status", ""))
            r_name = _esc(r.get("name", ""))
            r_status = _esc(r.get("status", "")).upper()
            r_cat = _esc(r.get("category", ""))
            r_details = _esc(r.get("details", "")[:80])
            del_url = _esc(r.get("delete_url", ""))
            del_link = f'<a href="{del_url}" target="_blank">Delete →</a>' if r.get("delete_url") and r.get("status") == "found" else ""
            html += f'<tr><td>{r_name}</td><td style="color:{col};font-weight:600">{r_status}</td><td>{r_cat}</td><td>{r_details}</td><td>{del_link}</td></tr>\n'
        return html

    u_rows = ""
    for r in [x for x in u_res if x.get("status") == "found"]:
        r_name = _esc(r.get("name", ""))
        r_cat = _esc(r.get("category", ""))
        r_url = _esc(r.get("profile_url", ""))
        r_conf = int(r.get("confidence", 0))
        u_rows += f'<tr><td>{r_name}</td><td>{r_cat}</td><td><a href="{r_url}" target="_blank">{r_url[:60]}</a></td><td>{r_conf}%</td></tr>\n'

    ai_html = ""
    if ai:
        score = ai.get("risk_score", 0)
        ai_html = f'<h2>AI Risk Analysis</h2><p><strong>Risk Score:</strong> {score}/100 — {ai.get("risk_level","")}</p><p>{ai.get("executive_summary","")}</p>'

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>GhostTrace Report — {email}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:32px;line-height:1.6}}
h1{{color:#a78bfa;margin-bottom:4px}}
h2{{color:#7c3aed;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:32px}}
.meta{{font-size:.85rem;color:#8b949e;margin-bottom:24px}}
table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:16px}}
th{{text-align:left;padding:8px 12px;background:#161b22;color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px}}
td{{padding:8px 12px;border-bottom:1px solid #21262d}}
tr:hover td{{background:#161b22}}
a{{color:#a78bfa}}
.found{{color:#ef4444;font-weight:600}}
.stat{{display:inline-block;padding:8px 20px;border-radius:8px;margin-right:12px;background:#161b22;border:1px solid #30363d}}
.stat-val{{font-size:1.8rem;font-weight:700;display:block}}
.stat-found .stat-val{{color:#ef4444}}
.stat-clean .stat-val{{color:#22c55e}}
.watermark{{margin-top:40px;font-size:.75rem;color:#484f58;border-top:1px solid #21262d;padding-top:12px}}
</style>
</head>
<body>
<h1>👻 GhostTrace Privacy Report</h1>
<div class="meta">
  Generated: {generated} &nbsp;·&nbsp;
  Email: <strong>{email}</strong>
  {f'&nbsp;·&nbsp; Username: <strong>@{u_name}</strong>' if u_name else ''}
</div>

<div>
  <div class="stat stat-found"><span class="stat-val">{found_count}</span>Accounts Found</div>
  <div class="stat stat-clean"><span class="stat-val">{sum(1 for r in surface+deep if r.get("status")=="not_found")}</span>Clean</div>
  <div class="stat"><span class="stat-val">{len(surface)}</span>Surface Checks</div>
  <div class="stat"><span class="stat-val">{len(deep)}</span>Deep Checks</div>
</div>

{ai_html}

<h2>Surface Scan Results ({len(surface)} platforms)</h2>
<table>
<tr><th>Platform</th><th>Status</th><th>Category</th><th>Details</th><th>Delete</th></tr>
{rows(surface)}
</table>

<h2>Deep Web Results ({len(deep)} sources)</h2>
<table>
<tr><th>Source</th><th>Status</th><th>Category</th><th>Details</th><th>Link</th></tr>
{rows(deep)}
</table>

{"<h2>Username Hunt — @" + u_name + " (" + str(len([x for x in u_res if x.get('status')=='found'])) + " found)</h2><table><tr><th>Platform</th><th>Category</th><th>Profile URL</th><th>Confidence</th></tr>" + u_rows + "</table>" if u_name and u_res else ""}

<div class="watermark">GhostTrace v4 — Local OSINT scanner · No data sent to external servers · {generated}</div>
</body>
</html>"""

    return Response(
        report,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="ghosttrace-{email}-{datetime.now().strftime("%Y%m%d")}.html"',
        },
    )


if __name__ == "__main__":
    from checkers.username.sites import USERNAME_SITES
    total = len(SURFACE_CHECKERS) + len(DEEP_CHECKERS)
    print(f"\n  GhostTrace v4 — AI-Powered Zero Footprint OSINT")
    print(f"  {len(SURFACE_CHECKERS)} surface + {len(DEEP_CHECKERS)} deep = {total} email checks")
    print(f"  {len(USERNAME_SITES)} username checks across platforms")
    print(f"  http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
