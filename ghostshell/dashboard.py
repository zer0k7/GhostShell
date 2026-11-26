"""GhostShell dashboard — shadcn-style UI.

Clean zinc palette, no emojis, no buzzwords, no dummy data.
Every number on the page comes from the SQLite database.
Fully responsive: stats stack on mobile, tables scroll horizontally.
"""
import sqlite3
from collections import Counter

from flask import Flask, jsonify, render_template_string

from . import db
from .enrichment import get_intel
from .profiler import profile_commands
from .rules import sigma_rule, suricata_rule

CSS = """
:root{
  --bg:#09090b; --card:#101013; --card-2:#18181b; --border:#27272a;
  --text:#fafafa; --muted:#a1a1aa; --faint:#71717a;
  --green:#22c55e; --red:#ef4444; --amber:#f59e0b; --blue:#60a5fa;
  --radius:10px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
.muted{color:var(--muted)} .faint{color:var(--faint)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}

/* top bar */
.topbar{position:sticky;top:0;z-index:10;background:rgba(9,9,11,.92);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
.topbar-inner{max-width:1200px;margin:0 auto;padding:0 20px;height:56px;
  display:flex;align-items:center;gap:20px}
.logo{font-weight:700;font-size:17px;letter-spacing:-.02em;color:var(--text)}
.logo span{color:var(--green)}
.topbar nav{display:flex;gap:18px;margin-left:auto}
.topbar nav a{color:var(--muted);font-size:14px}
.topbar nav a:hover{color:var(--text);text-decoration:none}
.live{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green)}

.wrap{max-width:1200px;margin:0 auto;padding:28px 20px 64px}
.page-head{display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px;margin-bottom:24px}
h1{font-size:26px;font-weight:700;letter-spacing:-.02em}
h2{font-size:16px;font-weight:600;letter-spacing:-.01em;margin-bottom:12px}
.page-head p{color:var(--muted);font-size:14px;margin-top:4px}

/* buttons / inputs */
.btn{display:inline-flex;align-items:center;gap:6px;background:var(--text);color:#09090b;
  padding:8px 14px;border-radius:8px;font-size:14px;font-weight:600;border:1px solid transparent;cursor:pointer}
.btn:hover{background:#e4e4e7;text-decoration:none}
.btn-ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--card-2);text-decoration:none}
input[type="search"]{background:var(--card);border:1px solid var(--border);color:var(--text);
  border-radius:8px;padding:8px 12px;font-size:14px;width:240px;max-width:100%;outline:none}
input[type="search"]:focus{border-color:var(--faint)}

/* stat cards */
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px}
.stat .label{font-size:13px;color:var(--muted)}
.stat .value{font-size:30px;font-weight:700;letter-spacing:-.03em;line-height:1.2;margin-top:2px}
.stat .sub{font-size:12px;color:var(--faint);margin-top:2px}

/* cards + tables */
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:20px}
.card-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px}
.table-wrap{overflow-x:auto;margin:0 -20px;padding:0 20px}
table{border-collapse:collapse;width:100%;min-width:760px;font-size:14px}
th{color:var(--muted);font-size:12px;font-weight:500;text-transform:uppercase;letter-spacing:.04em;
  text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:12px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--card-2)}
.empty{color:var(--muted);font-size:14px;padding:8px 0}

.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid transparent}
.b-bot{background:#27272a;color:#a1a1aa}
.b-mid{background:rgba(245,158,11,.12);color:#fbbf24;border-color:rgba(245,158,11,.35)}
.b-high{background:rgba(239,68,68,.12);color:#f87171;border-color:rgba(239,68,68,.35)}
.tag{display:inline-block;background:var(--card-2);border:1px solid var(--border);
  padding:2px 10px;border-radius:999px;font-size:12px;margin:2px 2px 2px 0}

/* terminal */
.term{background:#000;border:1px solid var(--border);border-radius:var(--radius);padding:18px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;line-height:1.7;
  color:#4ade80;white-space:pre-wrap;word-break:break-word;overflow-x:auto}
.term .cmd{color:#fafafa}
pre{background:#000;border:1px solid var(--border);border-radius:var(--radius);padding:16px;
  overflow:auto;font-size:12.5px;line-height:1.6;margin-bottom:20px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}
.meta div{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px}
.meta .label{font-size:12px;color:var(--muted)}
.meta .value{font-size:14px;font-weight:600;margin-top:2px;word-break:break-word}
footer{border-top:1px solid var(--border);padding-top:16px;color:var(--faint);font-size:13px}

@media (max-width:900px){ .grid{grid-template-columns:repeat(2,1fr)} }
@media (max-width:560px){
  .grid{grid-template-columns:1fr 1fr}
  .stat .value{font-size:24px}
  h1{font-size:22px}
  .topbar nav{display:none}
  .wrap{padding:20px 14px 48px}
  .card{padding:16px}
  .table-wrap{margin:0 -16px;padding:0 16px}
}
"""

PAGE = """
<!doctype html><html lang="en"><head><title>GhostShell</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>{{ css }}</style></head><body>
<header class="topbar"><div class="topbar-inner">
<a class="logo" href="/">Ghost<span>Shell</span></a>
<span class="live"><span class="dot"></span>Live</span>
<nav><a href="#sessions">Sessions</a><a href="#honeytokens">Honeytokens</a><a href="#panel">Panel attempts</a><a href="/api/ioc">IOC feed</a></nav>
</div></header>
<div class="wrap">
<div class="page-head"><div>
<h1>Sessions</h1>
<p>Every row is a real SSH login to the honeypot. Click a session to replay it.</p>
</div><a class="btn" href="/api/ioc">IOC feed (JSON)</a></div>

<div class="grid">
<div class="stat"><div class="label">Sessions</div><div class="value">{{ stats.sessions }}</div><div class="sub">{{ stats.ips }} unique IPs</div></div>
<div class="stat"><div class="label">Commands captured</div><div class="value">{{ stats.commands }}</div><div class="sub">across all sessions</div></div>
<div class="stat"><div class="label">Honeytoken hits</div><div class="value">{{ stats.honeytokens }}</div><div class="sub">canary files read</div></div>
<div class="stat"><div class="label">Top tactic</div><div class="value" style="font-size:20px;line-height:1.3;padding-top:6px">{{ stats.top_tactic or '—' }}</div><div class="sub">{{ stats.top_tactic_count }} sessions</div></div>
</div>

{% if tactics %}
<div class="card"><h2>Tactics seen</h2>
{% for t, n in tactics %}<span class="tag">{{ t }} · {{ n }}</span>{% endfor %}
</div>
{% endif %}

<div class="card" id="sessions"><div class="card-head">
<h2>All sessions</h2>
<input type="search" id="q" placeholder="Filter by IP or username…" oninput="filterRows()">
</div>
<div class="table-wrap"><table id="sessions-table">
<thead><tr><th>#</th><th>IP</th><th>Country</th><th>Credentials tried</th><th>SSH client</th><th>Cmds</th><th>Profile</th><th>Attack chain</th><th></th></tr></thead>
<tbody>
{% for s in sessions %}
<tr><td>{{ s.id }}</td>
<td class="mono">{{ s.src_ip }}</td>
<td>{{ s.intel.country }}<br><span class="faint">{{ s.intel.asn }}</span></td>
<td class="mono">{{ s.username }} / {{ s.password }}</td>
<td class="mono muted">{{ s.client_version or '—' }}</td>
<td>{{ s.command_count }}</td>
<td><span class="badge {{ 'b-high' if s.profile.score>=60 else 'b-mid' if s.profile.score>=25 else 'b-bot' }}">{{ s.profile.level }}</span><br><span class="faint">score {{ s.profile.score }}</span></td>
<td>{% for c in s.profile.chains %}<span class="tag">{{ c }}</span>{% else %}<span class="faint">—</span>{% endfor %}</td>
<td><a href="/session/{{ s.id }}">Replay</a> · <a href="/rules/{{ s.id }}">Rules</a></td></tr>
{% else %}<tr><td colspan="9" class="empty">No sessions yet. Try: ssh admin@localhost -p 2222</td></tr>
{% endfor %}
</tbody></table></div></div>

<div class="card" id="honeytokens"><h2>Honeytoken hits</h2>
{% if hits %}<div class="table-wrap"><table style="min-width:520px">
<thead><tr><th>Time</th><th>IP</th><th>File read</th></tr></thead><tbody>
{% for h in hits %}<tr><td class="mono">{{ h.ts[:19] }}</td><td class="mono">{{ h.src_ip }}</td><td class="mono">{{ h.token_path }}</td></tr>{% endfor %}
</tbody></table></div>
{% else %}<p class="empty">None yet. No attacker has read a canary file.</p>{% endif %}</div>

<div class="card" id="panel"><h2>Fake admin panel attempts</h2>
{% if http %}<div class="table-wrap"><table style="min-width:560px">
<thead><tr><th>Time</th><th>IP</th><th>Path</th><th>Credentials tried</th></tr></thead><tbody>
{% for h in http %}<tr><td class="mono">{{ h.ts[:19] }}</td><td class="mono">{{ h.src_ip }}</td><td class="mono">{{ h.path }}</td><td class="mono">{{ h.username }} / {{ h.password }}</td></tr>{% endfor %}
</tbody></table></div>
{% else %}<p class="empty">None yet. Visit http://localhost:8081 and try logging in.</p>{% endif %}</div>

<footer>GhostShell is a defensive research tool. Run it only on your own lab machine. Never expose ports 2222 / 5000 / 8081 to the internet.</footer>
</div>
<script>
function filterRows(){
  var q = document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('#sessions-table tbody tr').forEach(function(r){
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
setTimeout(function(){ location.reload(); }, 30000);
</script>
</body></html>
"""

REPLAY = """
<!doctype html><html lang="en"><head><title>Session {{ sid }} — GhostShell</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>{{ css }}</style></head><body>
<header class="topbar"><div class="topbar-inner">
<a class="logo" href="/">Ghost<span>Shell</span></a>
<nav><a href="/">All sessions</a><a href="/rules/{{ sid }}">Rules</a></nav>
</div></header>
<div class="wrap">
<p><a href="/">← All sessions</a></p>
<h1 style="margin-top:12px">Session {{ sid }}</h1>
<p class="muted">{{ src_ip }} · started {{ started }}</p>
<div class="meta">
<div><div class="label">Profile</div><div class="value">{{ profile.level }}</div></div>
<div><div class="label">Score</div><div class="value">{{ profile.score }}</div></div>
<div><div class="label">Commands</div><div class="value">{{ commands|length }}</div></div>
<div><div class="label">SSH client</div><div class="value mono">{{ client_version or '—' }}</div></div>
<div><div class="label">Auth attempts</div><div class="value">{{ auth_attempts }}</div></div>
<div><div class="label">Country</div><div class="value">{{ intel.country }} · {{ intel.asn }}</div></div>
</div>
<div class="card"><h2>MITRE ATT&amp;CK</h2>
<p style="margin-bottom:8px">Tactics: {% for t in profile.tactics %}<span class="tag">{{ t }}</span>{% else %}<span class="faint">none detected</span>{% endfor %}</p>
<p style="margin-bottom:8px">Techniques: {% for t in profile.techniques %}<span class="tag">{{ t }}</span>{% else %}<span class="faint">none detected</span>{% endfor %}</p>
<p>Attack chain: {% for c in profile.chains %}<span class="tag">{{ c }}</span>{% else %}<span class="faint">no chain detected</span>{% endfor %}</p>
<p class="faint" style="margin-top:8px">Tactic order: {{ profile.tactic_order | join(' → ') or '—' }}</p>
<p style="margin-top:12px"><a class="btn" href="/rules/{{ sid }}">Generate Sigma + Suricata rules</a></p>
</div>
<div class="card"><h2>Terminal replay</h2>
<div class="term">{% for c in commands %}<span class="cmd">$ {{ c.command }}</span>
{{ c.response }}{% endfor %}</div></div>
</div></body></html>
"""

RULES_PAGE = """
<!doctype html><html lang="en"><head><title>Rules — Session {{ sid }}</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>{{ css }}</style></head><body>
<header class="topbar"><div class="topbar-inner">
<a class="logo" href="/">Ghost<span>Shell</span></a>
<nav><a href="/">All sessions</a><a href="/session/{{ sid }}">Replay</a></nav>
</div></header>
<div class="wrap">
<p><a href="/">← All sessions</a> · <a href="/session/{{ sid }}">Replay session</a></p>
<h1 style="margin-top:12px">Detection rules — session {{ sid }}</h1>
<p class="muted" style="margin:6px 0 20px">Generated from this attacker's own commands and IP ({{ src_ip }}). Paste into your SIEM or IDS.</p>
<div class="card-head"><h2>Sigma</h2><button class="btn btn-ghost" onclick="copyText('sigma')">Copy</button></div>
<pre id="sigma">{{ sigma }}</pre>
<div class="card-head"><h2>Suricata</h2><button class="btn btn-ghost" onclick="copyText('suricata')">Copy</button></div>
<pre id="suricata">{{ suricata }}</pre>
</div>
<script>
function copyText(id){ navigator.clipboard.writeText(document.getElementById(id).innerText); }
</script>
</body></html>
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


def _stats(db_path, sessions, profiles):
    conn = sqlite3.connect(db_path)
    total_cmds = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    conn.close()
    tactic_counts = Counter()
    for p in profiles:
        for t in p["tactics"]:
            tactic_counts[t] += 1
    top = tactic_counts.most_common(1)
    return {
        "sessions": len(sessions),
        "commands": total_cmds,
        "honeytokens": len(db.get_honeytoken_hits(db_path)),
        "ips": len({s["src_ip"] for s in sessions}),
        "top_tactic": top[0][0] if top else None,
        "top_tactic_count": top[0][1] if top else 0,
    }


def create_app(config, db_path):
    app = Flask(__name__)

    @app.route("/")
    def index():
        sessions = db.get_sessions(db_path)
        profiles = []
        for s in sessions:
            cmds = db.get_commands(db_path, s["id"])
            s["profile"] = profile_commands([c["command"] for c in cmds])
            profiles.append(s["profile"])
            s["intel"] = get_intel(db_path, s["src_ip"])
        tactic_counts = Counter()
        for p in profiles:
            for t in p["tactics"]:
                tactic_counts[t] += 1
        return render_template_string(
            PAGE, css=CSS, sessions=sessions,
            hits=db.get_honeytoken_hits(db_path),
            http=_http_attempts(db_path),
            stats=_stats(db_path, sessions, profiles),
            tactics=sorted(tactic_counts.items(), key=lambda x: -x[1]),
        )

    @app.route("/session/<int:sid>")
    def replay(sid):
        commands = db.get_commands(db_path, sid)
        profile = profile_commands([c["command"] for c in commands])
        session = next((s for s in db.get_sessions(db_path, limit=200) if s["id"] == sid), {})
        return render_template_string(
            REPLAY, css=CSS, sid=sid, commands=commands, profile=profile,
            src_ip=session.get("src_ip", ""), started=(session.get("started_at") or "")[:19],
            client_version=session.get("client_version", ""),
            auth_attempts=session.get("auth_attempts", 1),
            intel=get_intel(db_path, session.get("src_ip", "")),
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
