import sqlite3

def get_connection():
    conn = sqlite3.connect("vault.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            token TEXT PRIMARY KEY, 
            pan_encrypted TEXT NOT NULL, 
            pan_hash TEXT UNIQUE NOT NULL, 
            masked_pan TEXT NOT NULL, 
            created_at TEXT NOT NULL, 
            last_used_at TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENTDON, 
            token TEXT NOT NULL, 
            action TEXT NOT NULL, 
            role TEXT NOT NULL, 
            timestamp TEXT NOT NULL, 
            reason TEXT
        )
    """)
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database and tables created successfully!")