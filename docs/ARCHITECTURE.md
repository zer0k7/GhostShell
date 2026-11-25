<div align="center">

![GhostShell Architecture](headings/fake-company.svg)

</div>

GhostShell is not one honeypot. It is a whole fake company that shares one fake world: same users, same files, same credentials, everywhere.

![GhostShell Architecture](architecture.svg)

![Components](headings/components.svg)

| File | Job |
|---|---|
| `ghostshell/honeypot.py` | Paramiko SSH server. Accepts any password — that is the trap. One thread per attacker. |
| `ghostshell/shell.py` | Fake shell. `ls`, `cat`, `ps`, `whoami`, `uname`, `sudo`, `curl`. Unknown commands go to the AI shell. |
| `ghostshell/fakefs.py` | The fake filesystem. Includes the honeytoken files. |
| `ghostshell/llm.py` | Local Ollama AI shell. No external API, no data leaves your machine. Falls back to rules when Ollama is off. |
| `ghostshell/services.py` | Fake admin panel + fake AWS metadata endpoint. Same fake AWS key as the SSH honeytoken. |
| `ghostshell/db.py` | SQLite. Tables: `sessions`, `commands`, `honeytoken_hits`, `http_attempts`. |
| `ghostshell/profiler.py` | Maps commands to MITRE ATT&CK tactics and techniques + skill score (bot / intermediate / skilled). |
| `ghostshell/rules.py` | Generates Sigma + Suricata rules from a session's own commands. |
| `ghostshell/dashboard.py` | Rich dark HTML dashboard: stats, session replay, MITRE profile, rules page, `/api/ioc`. |

![Data flow](headings/data-flow.svg)

```
1. Attacker SSHs in with admin / hunter123
        -> honeypot accepts, new session in the database
2. Attacker runs: ls, cat aws_credentials.txt, cat /etc/passwd
        -> fake shell answers from the fake filesystem
        -> every command is logged
        -> cat on a honeytoken is logged as a honeytoken hit
3. Attacker tries the stolen AWS key on the metadata endpoint
        -> fake metadata service logs the attempt, returns the same fake key
4. Dashboard reads the database
        -> profiler scores the session, maps MITRE tactics
        -> /session/<id> replays the terminal
        -> /rules/<id> generates Sigma + Suricata from the commands
        -> /api/ioc exposes attacker IPs + honeytoken hits as JSON
```

![Honeytokens](headings/honeytokens.svg)

| File | What it looks like | Signal |
|---|---|---|
| `/home/admin/aws_credentials.txt` | Real-looking AWS key pair | Attacker is after cloud creds |
| `/home/admin/.ssh/id_rsa` | Private SSH key | Attacker wants lateral movement |
| `/home/admin/database_backup.sql` | Prod DB dump with password hashes | Attacker wants data / creds |

Reading any of them is logged with timestamp, session and IP — in the dashboard under Honeytoken hits and in `/api/ioc`.

![From attack to detection](headings/attack-to-detection.svg)

Every session can be turned into defence in one click:

- **Sigma rule** — paste into Splunk / Sentinel / Elastic
- **Suricata rule** — paste into your IDS
- **IOC feed** — `GET /api/ioc` — attacker IPs, ready to blocklist

The rules are generated from the attacker's actual commands, not from a textbook list — so they match real behaviour.
