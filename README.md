# GhostShell — AI-Driven Deception Platform

> Not just a honeypot. GhostShell tricks attackers, profiles them, and turns their attacks into defence.

A normal SSH honeypot logs logins and dies when an attacker types an unusual command. GhostShell is different:

1. **AI fake shell** — a local LLM answers *any* command like a real Linux box (fake files, fake processes, fake errors), so attackers stay longer and reveal more.
2. **A whole fake company, not just SSH** — SSH + fake admin panel + fake MySQL + fake AWS metadata endpoint, all sharing the same fake users, files and credentials.
3. **Attacker profiling** — every session is scored (bot vs human, skill level, intent) and auto-mapped to MITRE ATT&CK.
4. **Honeytokens that phone home** — fake `aws_credentials.txt`, `id_rsa`, `database_backup.sql`. If an attacker downloads and uses them anywhere, you get an alert.
5. **Attacks become defence** — every attack auto-generates Sigma rules, Suricata rules and a blocklist of bad IPs / hashes.

Built by Salik Seraj Naik (zer0k7) — BTech CSE, red team / offensive security.

## Status

Week 1 (done): core SSH honeypot on port 2222, fake filesystem, fake shell, session + command logging to SQLite, live dashboard on port 5000 with session replay.

Week 2 (next): AI shell via Ollama, fake HTTP / MySQL services linked to the same fake company.
Week 3: attacker profiler + MITRE mapping + honeytokens.
Week 4: auto Sigma / Suricata rule generator + IOC feed + demo.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
```

- SSH honeypot: `ssh admin@localhost -p 2222` — any password works, it is a trap. Try `ls`, `cat aws_credentials.txt`, `ps aux`, `uname -a`.
- Dashboard: http://localhost:5000

> **Safety:** GhostShell is a defensive research tool. Run it only on your own lab machine / VM, never on a production server, and never point it at real systems. It accepts any password by design — that is the trap.

## Project layout

```
GhostShell/
  run.py                  # starts honeypot + dashboard
  config.yaml             # ports, banner, fake hostname
  ghostshell/
    honeypot.py           # Paramiko SSH server, accepts any auth
    shell.py              # fake shell: ls/cat/ps/whoami/... + AI fallback
    fakefs.py             # the fake filesystem (incl. honeytokens)
    llm.py                # Ollama AI shell, falls back to rules when offline
    db.py                 # SQLite: sessions, commands, honeytoken hits
    profiler.py           # MITRE ATT&CK mapping + skill scoring
    rules.py              # Sigma / Suricata generation from attacks
    dashboard.py          # Flask live dashboard + session replay
  data/
    ghostshell.db         # created on first run (gitignored)
```

## Resume line

*Built GhostShell, an AI-driven deception platform that profiles live attackers, maps them to MITRE ATT&CK, and auto-generates Sigma detection rules from real attacks.*
