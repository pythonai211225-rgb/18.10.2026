import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "messages.db"


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        columns = [r["name"] for r in db.execute("PRAGMA table_info(messages)")]
        if "user_id" not in columns:
            db.execute("ALTER TABLE messages ADD COLUMN user_id INTEGER REFERENCES users(id)")
        user_columns = [r["name"] for r in db.execute("PRAGMA table_info(users)")]
        for column, kind in (("avatar", "BLOB"), ("avatar_type", "TEXT"), ("avatar_preset", "TEXT")):
            if column not in user_columns:
                db.execute(f"ALTER TABLE users ADD COLUMN {column} {kind}")
