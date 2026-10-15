
import sqlite3

DATABASE = "securecampus.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_audit_table():
    """Create the audit log table if it does not already exist."""
    conn = get_db_connection()

    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def log_audit_event(username, action, details="", status="SUCCESS"):
    """Save an application event to the audit log."""
    conn = get_db_connection()

    try:
        conn.execute(
            """
            INSERT INTO audit_logs
                (username, action, details, status)
            VALUES (?, ?, ?, ?)
            """,
            (username, action, details, status),
        )
        conn.commit()
    finally:
        conn.close()