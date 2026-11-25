"""SQLite logging for GhostShell: sessions, commands, honeytoken hits."""
import os
import sqlite3
from datetime import datetime, timezone


def _connect(db_path):
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    conn = _connect(db_path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT, username TEXT, password TEXT,
            started_at TEXT, ended_at TEXT, command_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER, ts TEXT, command TEXT, response TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
        );
        CREATE TABLE IF NOT EXISTS honeytoken_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER, ts TEXT, token_path TEXT, src_ip TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
        );
        """
    )
    conn.commit()
    conn.close()


def _now():
    return datetime.now(timezone.utc).isoformat()


def new_session(db_path, src_ip, username, password):
    conn = _connect(db_path)
    cur = conn.execute(
        "INSERT INTO sessions (src_ip, username, password, started_at) VALUES (?,?,?,?)",
        (src_ip, username, password, _now()),
    )
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return sid


def end_session(db_path, session_id):
    conn = _connect(db_path)
    conn.execute(
        "UPDATE sessions SET ended_at=? WHERE id=?", (_now(), session_id)
    )
    conn.commit()
    conn.close()


def log_command(db_path, session_id, command, response):
    conn = _connect(db_path)
    conn.execute(
        "INSERT INTO commands (session_id, ts, command, response) VALUES (?,?,?,?)",
        (session_id, _now(), command, response[:2000]),
    )
    conn.execute(
        "UPDATE sessions SET command_count = command_count + 1 WHERE id=?",
        (session_id,),
    )
    conn.commit()
    conn.close()


def log_honeytoken(db_path, session_id, token_path, src_ip):
    conn = _connect(db_path)
    conn.execute(
        "INSERT INTO honeytoken_hits (session_id, ts, token_path, src_ip) VALUES (?,?,?,?)",
        (session_id, _now(), token_path, src_ip),
    )
    conn.commit()
    conn.close()


def get_sessions(db_path, limit=50):
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_commands(db_path, session_id):
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT * FROM commands WHERE session_id=? ORDER BY id", (session_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_honeytoken_hits(db_path, limit=50):
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT * FROM honeytoken_hits ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
