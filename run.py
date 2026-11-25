"""Start GhostShell: SSH honeypot (port 2222) + dashboard (port 5000)."""
import threading

import yaml

from ghostshell import dashboard, db, honeypot

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

DB_PATH = CONFIG.get("db_path", "data/ghostshell.db")

if __name__ == "__main__":
    db.init_db(DB_PATH)
    threading.Thread(target=honeypot.start, args=(CONFIG, DB_PATH), daemon=True).start()
    dashboard.start(CONFIG, DB_PATH)
