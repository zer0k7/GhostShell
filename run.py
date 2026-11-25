"""Start GhostShell — everything, today, in one command.

- SSH honeypot ......... port 2222  (any password works — it is a trap)
- Fake admin panel ..... port 8081  (fake Acme Corp portal + AWS metadata)
- Live dashboard ....... port 5000  (rich HTML: stats, replay, MITRE, rules, IOC feed)

Run only on your own lab machine / VM, never on production.
"""
import threading

import yaml

from ghostshell import dashboard, db, honeypot, services

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

DB_PATH = CONFIG.get("db_path", "data/ghostshell.db")

if __name__ == "__main__":
    db.init_db(DB_PATH)
    threading.Thread(target=honeypot.start, args=(CONFIG, DB_PATH), daemon=True).start()
    threading.Thread(target=services.start, args=(CONFIG, DB_PATH), daemon=True).start()
    dashboard.start(CONFIG, DB_PATH)
