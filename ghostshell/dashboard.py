"""GhostShell live dashboard — rich HTML, dark SOC-style UI.

Routes:
  /                 stats + sessions + honeytoken hits + HTTP attempts
  /session/<id>     terminal replay + MITRE profile
  /rules/<id>       auto-generated Sigma + Suricata rules for a session
  /api/sessions     JSON sessions
  /api/session/<id> JSON commands + profile
  /api/ioc          JSON IOC feed (attacker IPs, honeytoken hits)
"""
import sqlite3

from flask import Flask, jsonify, render_template_string

from . import db
from .profiler import profile_commands
from .rules import sigma_rule, suricata_rule

CSS = """
:root{--bg:#0b1220;--card:#111c33;--card2:#0f1930;--text:#e2e8f0;--muted:#94a3b8;
--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--blue:#3b82f6;--purple:#a855f7}
*{box-sizing:border-box} body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--text)}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
h1{font-size:32px;margin:0} h1 span{color:var(--green)}
.sub{color:var(--muted);margin:6px 0 24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid #1e293b;border-radius:14px;padding:18px}
.stat b{font-size:32px;display:block} .stat span{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid #1e293b;border-radius:14px;padding:20px;margin-bottom:20px}
h2{margin:0 0 14px;font-size:19px}
table{border-collapse:collapse;width:100%;font-size:14px}
td,th{padding:10px 8px;border-bottom:1px solid #1e293b;text-align:left}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
a{color:#60a5fa;text-decoration:none} a:hover{text-decoration:underline}
.badge{padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
.b-bot{background:#1e293b;color:#94a3b8} .b-mid{background:#451a03;color:#fbbf24}
.b-high{background:#450a0a;color:#f87171}
.term{background:#020617;border:1px solid #1e293b;border-radius:12px;padding:18px;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;line-height:1.6;
color:#4ade80;white-space:pre-wrap;word-break:break-word}
.term .cmd{color:#e2e8f0}
.tag{display:inline-block;background:#1e293b;padding:3px 10px;border-radius:20px;font-size:12px;margin:2px}
pre{background:#020617;border:1px solid #1e293b;border-radius:12px;padding:16px;
overflow:auto;font-size:12px;line-height:1.5}
.btn{display:inline-block;background:var(--blue);color:#fff;padding:8px 16px;border-radius:8px;font-size:14px}
.muted{color:var(--muted)}
"""

PAGE = """
<!doctype html><html><head><title>GhostShell — Live Attacks</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{{ css }}</style></head><body><div class="wrap">
<header><div><h1>👻 GhostShell <span>// live attacks</span></h1>
<p class="sub">AI deception platform — every login below is an attacker who fell for the trap.
Click a session to replay it like a terminal recording.</p></div>
<a class="btn" href="/api/ioc">⬇ IOC feed (JSON)</a></header>

<div class="grid">
<div class="stat"><b>{{ stats.sessions }}</b><span>attacker sessions</span></div>
<div class="stat"><b>{{ stats.commands }}</b><span>commands captured</span></div>
<div class="stat"><b>{{ stats.honeytokens }}</b><span>honeytoken hits</span></div>
<div class="stat"><b>{{ stats.ips }}</b><span>unique attacker IPs</span></div>
</div>

<div class="card"><h2>🎯 Sessions</h2>
<table><tr><th>#</th><th>IP</th><th>Credentials tried</th><th>Started</th><th>Cmds</th><th>Profile</th><th></th></tr>
{% for s in sessions %}
<tr><td>{{ s.id }}</td><td>{{ s.src_ip }}</td>
<td>{{ s.username }} / {{ s.password }}</td><td>{{ s.started_at[:19] }}</td>
<td>{{ s.command_count }}</td>
<td><span class="badge {{ 'b-high' if s.profile.score>=60 else 'b-mid' if s.profile.score>=25 else 'b-bot' }}">{{ s.profile.level }}</span></td>
<td><a href="/session/{{ s.id }}">Replay →</a> · <a href="/rules/{{ s.id }}">Rules</a></td></tr>
{% else %}<tr><td colspan="7" class="muted">No attackers yet. Try: ssh admin@localhost -p 2222</td></tr>
{% endfor %}</table></div>

<div class="card"><h2>🪤 Honeytoken hits</h2>
{% if hits %}<table><tr><th>Time</th><th>IP</th><th>Canary file they read</th></tr>
{% for h in hits %}<tr><td>{{ h.ts[:19] }}</td><td>{{ h.src_ip }}</td><td>{{ h.token_path }}</td></tr>{% endfor %}</table>
{% else %}<p class="muted">None yet — no attacker has touched a canary file.</p>{% endif %}</div>

<div class="card"><h2>🌐 Fake admin panel attempts</h2>
{% if http %}<table><tr><th>Time</th><th>IP</th><th>Path</th><th>Credentials tried</th></tr>
{% for h in http %}<tr><td>{{ h.ts[:19] }}</td><td>{{ h.src_ip }}</td><td>{{ h.path }}</td><td>{{ h.username }} / {{ h.password }}</td></tr>{% endfor %}</table>
{% else %}<p class="muted">None yet — visit http://localhost:8081 and try logging in.</p>{% endif %}</div>

<p class="muted">GhostShell is a defensive research tool. Run it only on your own lab machine, never on production.</p>
</div></body></html>
"""

REPLAY = """
<!doctype html><html><head><title>Session {{ sid }} — GhostShell</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{{ css }}</style></head><body><div class="wrap">
<p><a href="/">← All sessions</a></p>
<h1>Session {{ sid }} — {{ profile.level }}</h1>
<p class="sub">Score {{ profile.score }} · {{ src_ip }}</p>
<p>MITRE tactics: {% for t in profile.tactics %}<span class="tag">{{ t }}</span>{% endfor %}</p>
<p>Techniques: {% for t in profile.techniques %}<span class="tag">{{ t }}</span>{% endfor %}</p>
<p><a class="btn" href="/rules/{{ sid }}">Generate Sigma + Suricata rules</a></p>
<div class="term">{% for c in commands %}<span class="cmd">$ {{ c.command }}</span>
{{ c.response }}{% endfor %}</div>
</div></body></html>
"""

RULES_PAGE = """
<!doctype html><html><head><title>Rules — Session {{ sid }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{{ css }}</style></head><body><div class="wrap">
<p><a href="/">← All sessions</a> · <a href="/session/{{ sid }}">Replay session</a></p>
<h1>🛡 Detection rules — session {{ sid }} ({{ src_ip }})</h1>
<p class="sub">Auto-generated from the attacker's own commands. Paste these into your SIEM / IDS.</p>
<h2>Sigma</h2><pre>{{ sigma }}</pre>
<h2>Suricata</h2><pre>{{ suricata }}</pre>
</div></body></html>
"""


def _http_attempts(db_path, limit=20):
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM http_attempts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _stats(db_path, sessions):
    conn = sqlite3.connect(db_path)
    total_cmds = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    conn.close()
    return {
        "sessions": len(sessions),
        "commands": total_cmds,
        "honeytokens": len(db.get_honeytoken_hits(db_path)),
        "ips": len({s["src_ip"] for s in sessions}),
    }


def create_app(config, db_path):
    app = Flask(__name__)

    @app.route("/")
    def index():
        sessions = db.get_sessions(db_path)
        for s in sessions:
            cmds = db.get_commands(db_path, s["id"])
            s["profile"] = profile_commands([c["command"] for c in cmds])
        return render_template_string(
            PAGE, css=CSS, sessions=sessions,
            hits=db.get_honeytoken_hits(db_path),
            http=_http_attempts(db_path), stats=_stats(db_path, sessions),
        )

    @app.route("/session/<int:sid>")
    def replay(sid):
        commands = db.get_commands(db_path, sid)
        profile = profile_commands([c["command"] for c in commands])
        src_ip = ""
        for s in db.get_sessions(db_path, limit=200):
            if s["id"] == sid:
                src_ip = s["src_ip"]
        return render_template_string(
            REPLAY, css=CSS, sid=sid, commands=commands, profile=profile, src_ip=src_ip
        )

    @app.route("/rules/<int:sid>")
    def rules_page(sid):
        sessions = db.get_sessions(db_path, limit=200)
        src_ip = next((s["src_ip"] for s in sessions if s["id"] == sid), "?")
        commands = [c["command"] for c in db.get_commands(db_path, sid)]
        return render_template_string(
            RULES_PAGE, css=CSS, sid=sid, src_ip=src_ip,
            sigma=sigma_rule(src_ip, commands),
            suricata=suricata_rule(src_ip),
        )

    @app.route("/api/sessions")
    def api_sessions():
        return jsonify(db.get_sessions(db_path))

    @app.route("/api/session/<int:sid>")
    def api_session(sid):
        commands = db.get_commands(db_path, sid)
        return jsonify(
            {"commands": commands, "profile": profile_commands([c["command"] for c in commands])}
        )

    @app.route("/api/ioc")
    def api_ioc():
        sessions = db.get_sessions(db_path)
        return jsonify(
            {
                "attacker_ips": sorted({s["src_ip"] for s in sessions}),
                "honeytoken_hits": db.get_honeytoken_hits(db_path),
                "fake_aws_key": "AKIAIOSFODNN7FAKEKEY",
            }
        )

    return app


def start(config, db_path):
    app = create_app(config, db_path)
    port = int(config.get("dashboard_port", 5000))
    print(f"[+] GhostShell dashboard on http://localhost:{port}", flush=True)
    app.run(host=config.get("host", "0.0.0.0"), port=port, use_reloader=False)
