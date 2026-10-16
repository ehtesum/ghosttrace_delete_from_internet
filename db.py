import contextlib
import json
import os
import sqlite3
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghosttrace.db")


# FIX BUG-18: connection never closed — old _conn() returned a raw sqlite3 connection whose __exit__
# only committed/rolled-back but never called close(); contextmanager now guarantees close() in finally
@contextlib.contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                email        TEXT    NOT NULL,
                scanned_at   INTEGER NOT NULL,
                surface_json TEXT,
                deep_json    TEXT,
                ai_json      TEXT,
                found_count  INTEGER DEFAULT 0,
                breach_count INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_scan_email ON scans(email);
            CREATE INDEX IF NOT EXISTS idx_scan_time  ON scans(scanned_at);

            CREATE TABLE IF NOT EXISTS username_scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    NOT NULL,
                scanned_at   INTEGER NOT NULL,
                results_json TEXT,
                found_count  INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_user_scan ON username_scans(username);

            CREATE TABLE IF NOT EXISTS deletions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                email        TEXT    NOT NULL,
                platform_id  TEXT    NOT NULL,
                platform     TEXT    NOT NULL,
                confirmed_at INTEGER NOT NULL,
                notes        TEXT    DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_del_email ON deletions(email);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_del_unique ON deletions(email, platform_id);
        """)


def save_scan(email: str, surface: list, deep: list, ai_result=None) -> int:
    all_r = surface + deep
    found   = sum(1 for r in all_r if r.get("status") == "found")
    breaches = sum(1 for r in all_r if r.get("status") == "found" and r.get("category") == "breaches")
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (email,scanned_at,surface_json,deep_json,ai_json,found_count,breach_count)"
            " VALUES (?,?,?,?,?,?,?)",
            (
                email.strip().lower(),
                int(time.time()),
                json.dumps(surface),
                json.dumps(deep),
                json.dumps(ai_result) if ai_result else None,
                found,
                breaches,
            ),
        )
        return cur.lastrowid


def save_username_scan(username: str, results: list) -> int:
    found = sum(1 for r in results if r.get("status") == "found")
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO username_scans (username,scanned_at,results_json,found_count) VALUES (?,?,?,?)",
            (username.strip().lower(), int(time.time()), json.dumps(results), found),
        )
        return cur.lastrowid


def get_history(email: str = None, limit: int = 100) -> list:
    with _conn() as c:
        if email:
            rows = c.execute(
                "SELECT id,email,scanned_at,found_count,breach_count FROM scans"
                " WHERE email=? ORDER BY scanned_at DESC LIMIT ?",
                (email.strip().lower(), limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT id,email,scanned_at,found_count,breach_count FROM scans"
                " ORDER BY scanned_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["surface"] = json.loads(d.pop("surface_json") or "[]")
        d["deep"]    = json.loads(d.pop("deep_json")    or "[]")
        d["ai"]      = json.loads(d["ai_json"]) if d.get("ai_json") else None
        return d


def delete_scan(scan_id: int):
    with _conn() as c:
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))


def get_emails() -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT email, COUNT(*) as scan_count, MAX(scanned_at) as last_scan,"
            " MAX(found_count) as max_found, MAX(breach_count) as max_breaches"
            " FROM scans GROUP BY email ORDER BY last_scan DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_username_history(limit: int = 50) -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT id,username,scanned_at,found_count FROM username_scans"
            " ORDER BY scanned_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_username_scan(scan_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM username_scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["results"] = json.loads(d.pop("results_json") or "[]")
        return d


def diff_scans(old_id: int, new_id: int) -> dict:
    """Return accounts that appeared or disappeared between two scans."""
    old = get_scan(old_id)
    new = get_scan(new_id)
    if not old or not new:
        return {"error": "Scan not found"}

    def found_ids(scan):
        return {r["id"] for r in scan["surface"] + scan["deep"] if r.get("status") == "found"}

    old_found = found_ids(old)
    new_found = found_ids(new)

    def by_id(scan, ids):
        return [r for r in scan["surface"] + scan["deep"] if r["id"] in ids]

    return {
        "new_accounts":     by_id(new, new_found - old_found),
        "removed_accounts": by_id(old, old_found - new_found),
        "still_found":      by_id(new, new_found & old_found),
    }


# ── Deletion confirmation tracking ────────────────────────────────────────────

def confirm_deletion(email: str, platform_id: str, platform: str, notes: str = "") -> bool:
    """Mark a platform account as deleted. Returns True if newly confirmed."""
    with _conn() as c:
        try:
            c.execute(
                "INSERT OR REPLACE INTO deletions (email,platform_id,platform,confirmed_at,notes)"
                " VALUES (?,?,?,?,?)",
                (email.strip().lower(), platform_id, platform, int(time.time()), notes),
            )
            return True
        except Exception:
            return False


def unconfirm_deletion(email: str, platform_id: str):
    """Remove a deletion confirmation."""
    with _conn() as c:
        c.execute("DELETE FROM deletions WHERE email=? AND platform_id=?",
                  (email.strip().lower(), platform_id))


def get_deletions(email: str) -> list:
    """Get all confirmed deletions for an email."""
    with _conn() as c:
        rows = c.execute(
            "SELECT platform_id, platform, confirmed_at, notes"
            " FROM deletions WHERE email=? ORDER BY confirmed_at DESC",
            (email.strip().lower(),),
        ).fetchall()
        return [dict(r) for r in rows]
