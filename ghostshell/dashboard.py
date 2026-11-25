"""Live dashboard — Flask, reads the SQLite log.

Routes: / (sessions + honeytoken hits), /session/<id> (replay),
/api/sessions, /api/session/<id>.
"""
from flask import Flask, jsonify, render_template_string

from . import db
from .profiler import profile_commands

PAGE = """
<!doctype html><html><head><title>GhostShell</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px}
h1{font-size:28px} table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:8px;text-align:left} th{background:#111;color:#fff}
a{color:#0b5fff} .tag{background:#eee;padding:2px 8px;border-radius:10px;font-size:12px}</style>
</head><body>
<h1>👻 GhostShell — live attacks</h1>
<p>Every login below is an attacker who fell for the trap. Click a session to replay it.</p>
<h2>Sessions</h2>
<table><tr><th>#</th><th>IP</th><th>User / pass tried</th><th>Started</th><th>Cmds</th></tr>
{% for s in sessions %}
<tr><td><a href="/session/{{ s.id }}">{{ s.id }}</a></td><td>{{ s.src_ip }}</td>
<td>{{ s.username }} / {{ s.password }}</td><td>{{ s.started_at }}</td><td>{{ s.command_count }}</td></tr>
{% endfor %}</table>
<h2>Honeytoken hits</h2>
{% if hits %}<table><tr><th>Time</th><th>IP</th><th>File they read</th></tr>
{% for h in hits %}<tr><td>{{ h.ts }}</td><td>{{ h.src_ip }}</td><td>{{ h.token_path }}</td></tr>{% endfor %}</table>
{% else %}<p>None yet — no attacker has touched a canary file.</p>{% endif %}
</body></html>
"""

REPLAY = """
<!doctype html><html><head><title>Session {{ sid }} — GhostShell</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px}
pre{background:#111;color:#0f0;padding:16px;border-radius:8px;white-space:pre-wrap}
.tag{background:#eee;padding:2px 8px;border-radius:10px;font-size:12px}</style>
</head><body>
<h1>Session {{ sid }} — {{ profile.level }}</h1>
<p>MITRE tactics: {{ profile.tactics | join(', ') or 'none yet' }}</p>
<p>Techniques: {{ profile.techniques | join(', ') or 'none yet' }}</p>
<pre>{% for c in commands %}$ {{ c.command }}
{{ c.response }}{% endfor %}</pre>
<p><a href="/">← back to all sessions</a></p>
</body></html>
"""


def create_app(config, db_path):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(
            PAGE,
            sessions=db.get_sessions(db_path),
            hits=db.get_honeytoken_hits(db_path),
        )

    @app.route("/session/<int:sid>")
    def replay(sid):
        commands = db.get_commands(db_path, sid)
        profile = profile_commands([c["command"] for c in commands])
        return render_template_string(REPLAY, sid=sid, commands=commands, profile=profile)

    @app.route("/api/sessions")
    def api_sessions():
        return jsonify(db.get_sessions(db_path))

    @app.route("/api/session/<int:sid>")
    def api_session(sid):
        commands = db.get_commands(db_path, sid)
        return jsonify({"commands": commands, "profile": profile_commands([c["command"] for c in commands])})

    return app


def start(config, db_path):
    app = create_app(config, db_path)
    port = int(config.get("dashboard_port", 5000))
    print(f"[+] GhostShell dashboard on http://localhost:{port}", flush=True)
    app.run(host=config.get("host", "0.0.0.0"), port=port, use_reloader=False)
