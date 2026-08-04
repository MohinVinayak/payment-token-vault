
from app.db import get_connection
from datetime import datetime,UTC

def fetch_by_token(token:str):
    conn = get_connection()
    
    cursor = conn.execute(
        "SELECT * FROM vault WHERE token = ?",(token,)
    )
    row = cursor.fetchone()
    conn.close()
    return row

def find_by_hash(pan_hash:str):
    conn = get_connection()
    cursor = conn.execute(
        "SELECT * FROM vault WHERE pan_hash = ?",(pan_hash,)
    )
    row = cursor.fetchone()
    conn.close()
    return row
    
def token_exists(token:str)->bool:
    conn = get_connection()
    cursor = conn.execute("SELECT 1 FROM vault WHERE token = ?",
                          (token,)
                          )
    row = cursor.fetchone()
    conn.close()
    return row is not None

def insert_token(token: str,
    pan_encrypted: str,
    pan_hash: str,
    masked_pan: str,):
    conn = get_connection()
    now = datetime.now(UTC)
    conn.execute("INSERT INTO vault (token,pan_encrypted, pan_hash, masked_pan, created_at, last_used_at) VALUES(?,?,?,?,?,?) ",(token,pan_encrypted, pan_hash, masked_pan, now, None),)
    conn.commit()
    conn.close()
    
def log_event(token: str, action: str, role: str, reason: str|None = None,):
    conn = get_connection()
    now = datetime.now(UTC)
    conn.execute("INSERT INTO audit_log(token,action,role,timestamp,reason) VALUES(?,?,?,?,?)", (token,action,role,now,reason),)
    conn.commit()
    conn.close()

def fetch_all_audit_logs():
    conn = get_connection()

    cursor = conn.execute("SELECT * FROM audit_log")

    rows = cursor.fetchall()

    conn.close()

    return rows


def log_detokenize_and_update(
  token: str,
  role:str,
  reason: str |None= None,  
):
    conn= get_connection()
    
    try:
        now= datetime.now(UTC)
        
        conn.execute("""INSERT INTO audit_log
            (token, action, role, timestamp, reason)
            VALUES (?, ?, ?, ?, ?)""", (token,"detokenize",role,now,reason), )
        
        conn.execute(
            """
            UPDATE vault
            SET last_used_at = ?
            WHERE token = ?
            """,
            (now, token),
        )
        
        conn.commit()
    except Exception:
        
        conn.rollback()
        raise
    finally:
        conn.close()