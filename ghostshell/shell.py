"""Fake shell: answers common Linux commands plausibly.

Unknown commands go to the local LLM (Ollama) if it is running,
otherwise to a realistic 'command not found'.
"""
from . import fakefs
from .llm import ai_response

FAKE_PS = """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 167584  9344 ?        Ss   Nov24   0:02 /sbin/init
root         512  0.0  0.0  12144  3456 ?        Ss   Nov24   0:00 /usr/sbin/sshd -D
root         884  0.0  0.2  72344 18200 ?        Ssl  Nov24   0:11 /usr/bin/dockerd -H fd://
admin       1042  0.0  0.0  17892  4200 pts/0    Ss   10:02   0:00 -bash
root        1204  0.0  0.1  44210  9100 ?        S    Nov24   0:03 /usr/bin/python3 /opt/app/server.py
"""

FAKE_UNAME = "Linux ubuntu-prod-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"


class FakeShell:
    def __init__(self, config, db_path, session_id, src_ip, username="admin"):
        self.config = config
        self.db_path = db_path
        self.session_id = session_id
        self.src_ip = src_ip
        self.username = username
        self.cwd = "/home/admin"
        self.hostname = config.get("fake_hostname", "ubuntu-prod-01")

    def prompt(self):
        return f"{self.username}@{self.hostname}:{self.cwd}$ "

    def handle(self, raw):
        cmd = raw.strip()
        if not cmd:
            return "", False
        parts = cmd.split()
        base = parts[0]
        out, should_exit = "", False

        if base in ("exit", "logout"):
            out, should_exit = "logout\n", True
        elif base == "pwd":
            out = self.cwd + "\n"
        elif base == "whoami":
            out = self.username + "\n"
        elif base == "id":
            out = f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\n"
        elif base == "hostname":
            out = self.hostname + "\n"
        elif base == "uname":
            out = FAKE_UNAME if "-a" in parts else "Linux\n"
        elif base == "ls":
            out = self._ls(parts[1:])
        elif base == "cd":
            out = self._cd(parts[1] if len(parts) > 1 else "/home/admin")
        elif base == "cat":
            out = self._cat(parts[1:])
        elif base == "echo":
            out = " ".join(parts[1:]) + "\n"
        elif base == "ps":
            out = FAKE_PS
        elif base == "env":
            out = f"USER={self.username}\nHOME=/home/{self.username}\nPWD={self.cwd}\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        elif base == "history":
            out = "    1  ls\n    2  cat notes.txt\n    3  ps aux\n"
        elif base in ("clear",):
            out = "\x1b[2J\x1b[H"
        elif base in ("curl", "wget"):
            # Log it — attackers fetching a payload is high-value intel.
            out = "curl: (7) Failed to connect to host: Connection timed out\n"
        elif base == "sudo":
            out = f"[sudo] password for {self.username}: \nSorry, try again.\n"
        elif base in ("rm", "mkdir", "touch", "cp", "mv", "chmod"):
            out = ""
        elif base in ("ifconfig", "ip"):
            out = "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        elif base == "netstat":
            out = "Active Internet connections (servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n"
        else:
            ai = ai_response(
                self.config.get("ollama_url", "http://localhost:11434"),
                self.config.get("ollama_model", "llama3.2:1b"),
                cmd,
                self.cwd,
            )
            out = (ai + "\n") if ai else f"bash: {base}: command not found\n"

        # Honeytoken check: reading a canary file is the signal.
        if base == "cat":
            for arg in parts[1:]:
                p = fakefs.normalise(self.cwd, arg)
                if p in fakefs.HONEYTOKENS:
                    from .db import log_honeytoken

                    log_honeytoken(self.db_path, self.session_id, p, self.src_ip)
        return out, should_exit

    def _ls(self, args):
        target = self.cwd
        show_all = False
        for a in args:
            if a.startswith("-"):
                if "a" in a:
                    show_all = True
            else:
                target = a
        path = fakefs.normalise(self.cwd, target)
        listing = fakefs.list_dir(path)
        if listing is None:
            return f"ls: cannot access '{target}': No such file or directory\n"
        dirs, files = listing
        items = dirs + files
        if show_all:
            items = [".", ".."] + items
        return ("  ".join(items) + "\n") if items else ""

    def _cd(self, target):
        path = fakefs.normalise(self.cwd, target)
        if fakefs.is_dir(path):
            self.cwd = path
            return ""
        if fakefs.exists(path):
            return f"bash: cd: {target}: Not a directory\n"
        return f"bash: cd: {target}: No such file or directory\n"

    def _cat(self, args):
        if not args:
            return "cat: missing operand\n"
        outs = []
        for arg in args:
            path = fakefs.normalise(self.cwd, arg)
            if fakefs.is_dir(path):
                outs.append(f"cat: {arg}: Is a directory\n")
            elif fakefs.exists(path):
                outs.append(fakefs.read_file(path))
            else:
                outs.append(f"cat: {arg}: No such file or directory\n")
        return "".join(outs)
