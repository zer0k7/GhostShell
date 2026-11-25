"""Fake shell — now STATEFUL.

Each session gets its own FakeFS, so mkdir / touch / echo > file /
rm actually change the machine the attacker sees. History and env
vars persist for the session. Unknown commands go to the local LLM
(Ollama) if it is running, otherwise to a realistic error.
"""
from . import fakefs
from .fakefs import FakeFS
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
        self.fs = FakeFS()
        self.history = []
        self.env = {
            "USER": username, "HOME": f"/home/{username}", "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }

    def prompt(self):
        return f"{self.username}@{self.hostname}:{self.cwd}$ "

    def handle(self, raw):
        cmd = raw.strip()
        if not cmd:
            return "", False
        self.history.append(cmd)
        # redirection: echo text > file  /  echo text >> file
        if ">" in cmd and cmd.split()[0] == "echo":
            return self._echo_redirect(cmd)
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
        elif base == "export":
            out = self._export(parts[1:])
        elif base == "ps":
            out = FAKE_PS
        elif base == "env":
            out = "".join(f"{k}={v}\n" for k, v in self.env.items()) + f"PWD={self.cwd}\n"
        elif base == "history":
            out = "".join(f"  {i+1:4d}  {h}\n" for i, h in enumerate(self.history))
        elif base == "clear":
            out = "\x1b[2J\x1b[H"
        elif base == "mkdir":
            out = self._mkdir(parts[1:])
        elif base == "touch":
            out = self._touch(parts[1:])
        elif base in ("rm", "rmdir"):
            out = self._rm(parts[1:], base == "rmdir")
        elif base == "cp":
            out = self._cp(parts[1:])
        elif base == "mv":
            out = self._mv(parts[1:])
        elif base in ("curl", "wget"):
            out = "curl: (7) Failed to connect to host: Connection timed out\n"
        elif base == "sudo":
            out = f"[sudo] password for {self.username}: \nSorry, try again.\n"
        elif base == "crontab":
            out = "no crontab for admin\n" if "-l" in parts else ""
        elif base in ("chmod",):
            out = ""
        elif base in ("vim", "vi", "nano", "less", "more"):
            out = f"Vim: {parts[1] if len(parts) > 1 else ''} — file opened (read-only in this session)\n"
        elif base in ("top", "htop"):
            out = "top - 10:02:11 up 1 day,  2 users,  load average: 0.12, 0.08, 0.05\n  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n  884 root      20   0  72344  18200   9100 S   0.0   0.2   0:11.02 dockerd\n 1204 root      20   0  44210   9100   4200 S   0.0   0.1   0:03.11 server.py\n"
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

        if base == "cat":
            for arg in parts[1:]:
                p = fakefs.normalise(self.cwd, arg)
                if p in fakefs.HONEYTOKENS:
                    from .db import log_honeytoken

                    log_honeytoken(self.db_path, self.session_id, p, self.src_ip)
        return out, should_exit

    # -- filesystem commands (stateful) --
    def _echo_redirect(self, cmd):
        append = ">>" in cmd
        sep = ">>" if append else ">"
        text, target = cmd.split(sep, 1)
        text = text[len("echo"):].strip().strip('"').strip("'")
        path = fakefs.normalise(self.cwd, target.strip())
        if self.fs.is_dir(path):
            return f"bash: {target.strip()}: Is a directory\n", False
        self.fs.write_file(path, text + "\n", append=append)
        return "", False

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
        listing = self.fs.list_dir(path)
        if listing is None:
            return f"ls: cannot access '{target}': No such file or directory\n"
        dirs, files = listing
        items = dirs + files
        if show_all:
            items = [".", ".."] + items
        return ("  ".join(items) + "\n") if items else ""

    def _cd(self, target):
        path = fakefs.normalise(self.cwd, target)
        if self.fs.is_dir(path):
            self.cwd = path
            return ""
        if self.fs.exists(path):
            return f"bash: cd: {target}: Not a directory\n"
        return f"bash: cd: {target}: No such file or directory\n"

    def _cat(self, args):
        if not args:
            return "cat: missing operand\n"
        outs = []
        for arg in args:
            path = fakefs.normalise(self.cwd, arg)
            if self.fs.is_dir(path):
                outs.append(f"cat: {arg}: Is a directory\n")
            elif self.fs.exists(path):
                outs.append(self.fs.read_file(path))
            else:
                outs.append(f"cat: {arg}: No such file or directory\n")
        return "".join(outs)

    def _export(self, args):
        for a in args:
            if "=" in a:
                k, v = a.split("=", 1)
                self.env[k] = v
        return ""

    def _mkdir(self, args):
        outs = []
        for a in [x for x in args if not x.startswith("-")]:
            p = fakefs.normalise(self.cwd, a)
            if not self.fs.mkdir(p):
                outs.append(f"mkdir: cannot create directory '{a}': File exists\n")
        return "".join(outs)

    def _touch(self, args):
        for a in [x for x in args if not x.startswith("-")]:
            self.fs.touch(fakefs.normalise(self.cwd, a))
        return ""

    def _rm(self, args, dir_only=False):
        outs = []
        for a in [x for x in args if not x.startswith("-")]:
            p = fakefs.normalise(self.cwd, a)
            if not self.fs.remove(p):
                outs.append(f"rm: cannot remove '{a}': No such file or directory\n")
        return "".join(outs)

    def _cp(self, args):
        args = [x for x in args if not x.startswith("-")]
        if len(args) < 2:
            return "cp: missing destination file operand\n"
        src = fakefs.normalise(self.cwd, args[0])
        dst = fakefs.normalise(self.cwd, args[1])
        if not self.fs.exists(src) or self.fs.is_dir(src):
            return f"cp: cannot stat '{args[0]}': No such file or directory\n"
        self.fs.write_file(dst, self.fs.read_file(src))
        return ""

    def _mv(self, args):
        args = [x for x in args if not x.startswith("-")]
        if len(args) < 2:
            return "mv: missing destination file operand\n"
        src = fakefs.normalise(self.cwd, args[0])
        dst = fakefs.normalise(self.cwd, args[1])
        if not self.fs.exists(src):
            return f"mv: cannot stat '{args[0]}': No such file or directory\n"
        content = self.fs.read_file(src)
        self.fs.remove(src)
        if content is None:
            self.fs.mkdir(dst)
        else:
            self.fs.write_file(dst, content)
        return ""
