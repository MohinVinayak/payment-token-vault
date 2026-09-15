import json
from datetime import datetime, UTC

from app.db import get_connection


# ── Vault ──────────────────────────────────────────────

def fetch_by_token(token: str) -> dict | None:
    """Find a vault record by its token."""
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM vault WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()
    return row


def find_by_hash(pan_hash: str) -> dict | None:
    """Find a vault record by its PAN hash (used for dedup)."""
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM vault WHERE pan_hash = ?", (pan_hash,))
    row = cursor.fetchone()
    conn.close()
    return row


def token_exists(token: str) -> bool:
    """Check if a token already exists in the vault."""
    conn = get_connection()
    cursor = conn.execute("SELECT 1 FROM vault WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def insert_token(
    token: str,
    pan_encrypted: str,
    pan_hash: str,
    masked_pan: str,
    expires_at: str | None = None,
) -> None:
    """Insert a new tokenized card into the vault."""
    conn = get_connection()
    now = datetime.now(UTC).isoformat()
    conn.execute(
        """INSERT INTO vault
           (token, pan_encrypted, pan_hash, masked_pan, created_at, last_used_at, expires_at, is_revoked)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (token, pan_encrypted, pan_hash, masked_pan, now, None, expires_at, 0),
    )
    conn.commit()
    conn.close()


def revoke_token(token: str) -> None:
    """Mark a token as revoked."""
    conn = get_connection()
    conn.execute("UPDATE vault SET is_revoked = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()


# ── Audit Log ──────────────────────────────────────────

def log_event(
    token: str, action: str, role: str, reason: str | None = None
) -> None:
    """Insert a single audit log entry."""
    conn = get_connection()
    now = datetime.now(UTC).isoformat()
    conn.execute(
        "INSERT INTO audit_log (token, action, role, timestamp, reason) VALUES (?, ?, ?, ?, ?)",
        (token, action, role, now, reason),
    )
    conn.commit()
    conn.close()


def fetch_all_audit_logs() -> list:
    """Return all audit log entries."""
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def log_detokenize_and_update(
    token: str, role: str, reason: str | None = None
) -> None:
    """Insert detokenize audit log and update last_used_at in one transaction."""
    conn = get_connection()
    try:
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO audit_log (token, action, role, timestamp, reason) VALUES (?, ?, ?, ?, ?)",
            (token, "detokenize", role, now, reason),
        )
        conn.execute(
            "UPDATE vault SET last_used_at = ? WHERE token = ?",
            (now, token),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Users ──────────────────────────────────────────────

def create_user(username: str, password_hash: str, role: str) -> None:
    """Insert a new user into the users table."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role),
    )
    conn.commit()
    conn.close()


def find_user(username: str) -> dict | None:
    """Find a user by username."""
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row


# ── Idempotency ───────────────────────────────────────

def find_idempotency(key: str) -> dict | None:
    """Look up a cached response by idempotency key."""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT * FROM idempotency_store WHERE key = ?", (key,)
    )
    row = cursor.fetchone()
    conn.close()
    return row


def insert_idempotency(key: str, response: dict) -> None:
    """Cache a response for an idempotency key."""
    conn = get_connection()
    now = datetime.now(UTC).isoformat()
    conn.execute(
        "INSERT INTO idempotency_store (key, response, created_at) VALUES (?, ?, ?)",
        (key, json.dumps(response), now),
    )
    conn.commit()
    conn.close()