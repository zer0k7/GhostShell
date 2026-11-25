"""GhostShell SSH honeypot — Paramiko server, accepts ANY password.

That is the trap: every login succeeds, every command is logged,
and the attacker lands in the fake shell.
"""
import os
import socket
import threading

import paramiko

from . import db
from .shell import FakeShell


class _Server(paramiko.ServerInterface):
    def __init__(self, src_ip):
        self.src_ip = src_ip
        self.username = None
        self.password = None
        self.auth_attempts = 0
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.auth_attempts += 1
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        # Reject key auth so attackers must use a password — that is
        # the credential we want to capture and log.
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def _handle_client(client, config, db_path):
    src_ip = client.getpeername()[0]
    transport = paramiko.Transport(client)
    host_key_path = config.get("host_key_path", "data/host_key")
    os.makedirs(os.path.dirname(host_key_path) or ".", exist_ok=True)
    if not os.path.exists(host_key_path):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(host_key_path)
    else:
        key = paramiko.RSAKey(filename=host_key_path)
    transport.add_server_key(key)

    server = _Server(src_ip)
    try:
        transport.start_server(server=server)
    except Exception:
        return
    chan = transport.accept(20)
    if chan is None:
        return
    if not server.event.wait(10):
        return

    client_version = getattr(transport, "remote_version", "") or ""
    session_id = db.new_session(
        db_path, src_ip, server.username or "?", server.password or "?",
        client_version=client_version, auth_attempts=max(server.auth_attempts, 1),
    )
    print(f"[+] login {src_ip} as {server.username} [{client_version}] (session {session_id})", flush=True)
    # GeoIP/ASN enrichment in the background — never blocks the shell.
    from .enrichment import enrich_ip

    threading.Thread(target=enrich_ip, args=(db_path, src_ip), daemon=True).start()

    shell = FakeShell(config, db_path, session_id, src_ip, server.username or "admin")
    chan.send(f"Welcome to {config.get('banner', 'Ubuntu 22.04.4 LTS')}\r\n")
    chan.send(shell.prompt())
    buf = b""
    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break
            buf += data
            while b"\n" in buf or b"\r" in buf:
                line, buf = buf.replace(b"\r", b"\n").split(b"\n", 1)
                cmd = line.decode("utf-8", "ignore").strip()
                if not cmd:
                    chan.send(shell.prompt())
                    continue
                out, should_exit = shell.handle(cmd)
                db.log_command(db_path, session_id, cmd, out)
                chan.send(out.replace("\n", "\r\n"))
                if should_exit:
                    chan.close()
                    break
                chan.send(shell.prompt())
            if chan.closed:
                break
    except Exception:
        pass
    finally:
        db.end_session(db_path, session_id)
        print(f"[-] session {session_id} from {src_ip} ended", flush=True)
        try:
            chan.close()
        except Exception:
            pass
        transport.close()


def start(config, db_path):
    db.init_db(db_path)
    host = config.get("host", "0.0.0.0")
    port = int(config.get("ssh_port", 2222))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(50)
    print(f"[+] GhostShell SSH honeypot listening on {host}:{port}", flush=True)
    while True:
        client, _ = sock.accept()
        threading.Thread(target=_handle_client, args=(client, config, db_path), daemon=True).start()
