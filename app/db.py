import sqlite3


DB_PATH = "vault.db"


def get_connection():
    """Create and return a new SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create all tables and indexes if they don't exist."""
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            token TEXT PRIMARY KEY,
            pan_encrypted TEXT NOT NULL,
            pan_hash TEXT UNIQUE NOT NULL,
            masked_pan TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT,
            is_revoked INTEGER DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            action TEXT NOT NULL,
            role TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            reason TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'service'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS idempotency_store (
            key TEXT PRIMARY KEY,
            response TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Indexes for faster lookups
    conn.execute("CREATE INDEX IF NOT EXISTS ix_vault_pan_hash ON vault(pan_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_token ON audit_log(token)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_timestamp ON audit_log(timestamp)")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database and tables created successfully!")