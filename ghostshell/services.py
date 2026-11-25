"""Fake company services — same fake world as the SSH honeypot.

- Fake admin login panel on port 8081: any username/password works,
  every attempt is logged to the same SQLite DB.
- Fake AWS metadata endpoint: /latest/meta-data/iam/security-credentials/
  returns the same fake AWS key that lives in the SSH honeytoken file.
  If an attacker steals the key from SSH and tries it here, both
  hits are linked by the same key.
"""
import sqlite3

from flask import Flask, jsonify, request

from . import db as gsdb

FAKE_AWS_KEY = "AKIAIOSFODNN7FAKEKEY"

LOGIN_PAGE = """
<!doctype html><html><head><title>Acme Corp — Internal Portal</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;padding-top:120px}
.card{background:#1e293b;padding:32px;border-radius:12px;width:340px}
input{width:100%;padding:10px;margin:8px 0;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff}
button{width:100%;padding:10px;background:#2563eb;color:#fff;border:0;border-radius:6px;cursor:pointer}</style>
</head><body><div class="card">
<h2>Acme Corp — Internal Portal</h2>
<p style="color:#94a3b8">Sign in to continue</p>
<form method="post" action="/login">
<input name="username" placeholder="Username">
<input name="password" type="password" placeholder="Password">
<button>Sign in</button></form></div></body></html>
"""


def _log_http(db_path, src_ip, username, password, path):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS http_attempts "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, src_ip TEXT, "
        "username TEXT, password TEXT, path TEXT)"
    )
    from datetime import datetime, timezone

    conn.execute(
        "INSERT INTO http_attempts (ts, src_ip, username, password, path) "
        "VALUES (?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), src_ip, username, password, path),
    )
    conn.commit()
    conn.close()


def create_app(config, db_path):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return LOGIN_PAGE

    @app.route("/login", methods=["POST"])
    def login():
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        _log_http(db_path, request.remote_addr, u, p, "/login")
        return (
            "<h1>Welcome, admin</h1><p>Dashboard loading…</p>"
            "<p>Servers: ubuntu-prod-01 (10.0.0.15) · db.internal (10.0.0.20)</p>"
        )

    @app.route("/latest/meta-data/iam/security-credentials/")
    def metadata():
        _log_http(db_path, request.remote_addr, "", "", request.path)
        return "acme-prod-role"

    @app.route("/latest/meta-data/iam/security-credentials/acme-prod-role")
    def metadata_role():
        _log_http(db_path, request.remote_addr, "", "", request.path)
        return jsonify(
            {
                "AccessKeyId": FAKE_AWS_KEY,
                "SecretAccessKey": "wJalrXUtnFEMIfakeSecretKey1234567890",
                "Token": "FAKE-SESSION-TOKEN",
                "Expiration": "2026-11-26T00:00:00Z",
            }
        )

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "acme-internal-portal"})

    return app


def start(config, db_path):
    app = create_app(config, db_path)
    port = int(config.get("fake_http_port", 8081))
    print(f"[+] Fake admin panel on http://localhost:{port}", flush=True)
    app.run(host=config.get("host", "0.0.0.0"), port=port, use_reloader=False)
