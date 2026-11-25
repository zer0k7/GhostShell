"""The fake filesystem the attacker sees.

Honeytokens are real-looking secrets. Reading one is logged as a
honeytoken hit — in Week 3 these also become canary alerts.
"""
import posixpath

# path -> content (None = directory)
FILES = {
    "/": None,
    "/home": None,
    "/home/admin": None,
    "/home/admin/.ssh": None,
    "/home/admin/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE-KEY-DO-NOT-USE-bXlzdGVyeWtleQ==\n-----END OPENSSH PRIVATE KEY-----\n",
    "/home/admin/.ssh/id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7fake admin@ubuntu-prod-01\n",
    "/home/admin/aws_credentials.txt": "[default]\naws_access_key_id = AKIAIOSFODNN7FAKEKEY\naws_secret_access_key = wJalrXUtnFEMIfakeSecretKey1234567890\n",
    "/home/admin/database_backup.sql": "-- MySQL dump 10.19\n-- Host: db.internal  Database: prod_users\nCREATE TABLE users (id INT, email VARCHAR(255), password_hash VARCHAR(255));\nINSERT INTO users VALUES (1,'admin@acme-corp.local','$2b$12$fakehash');\n",
    "/home/admin/.bash_history": "mysql -u root -p\naws s3 ls s3://acme-backups\nscp backup.tar.gz admin@10.0.0.12:/tmp/\n",
    "/home/admin/notes.txt": "TODO: rotate prod DB password, ask ops about the new VPN.\n",
    "/etc": None,
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "/etc/hostname": "ubuntu-prod-01\n",
    "/var": None,
    "/var/www": None,
    "/var/www/html": None,
    "/var/www/html/index.html": "<html><body><h1>Acme Corp — Internal Portal</h1></body></html>\n",
    "/var/log": None,
    "/var/log/auth.log": "Nov 25 10:02:11 ubuntu-prod-01 sshd[1042]: Accepted password for admin from 10.0.0.5 port 51234 ssh2\n",
    "/tmp": None,
    "/opt": None,
    "/opt/app": None,
    "/opt/app/config.yml": "db_host: db.internal\ndb_user: app\n# db_pass is in the vault, do not commit it here\n",
}

HONEYTOKENS = {
    "/home/admin/aws_credentials.txt",
    "/home/admin/.ssh/id_rsa",
    "/home/admin/database_backup.sql",
}


def normalise(cwd, path):
    if not path:
        return cwd
    if path.startswith("/"):
        p = posixpath.normpath(path)
    else:
        p = posixpath.normpath(posixpath.join(cwd, path))
    return p if p.startswith("/") else "/" + p


def is_dir(path):
    return path in FILES and FILES[path] is None


def exists(path):
    return path in FILES


def list_dir(path):
    """Return (dirs, files) directly under path, or None if not a dir."""
    if not is_dir(path):
        return None
    prefix = path if path == "/" else path + "/"
    dirs, files = [], []
    for p, content in FILES.items():
        if p == path or not p.startswith(prefix):
            continue
        rest = p[len(prefix):]
        if "/" in rest:
            continue
        (dirs if content is None else files).append(rest)
    return sorted(dirs), sorted(files)


def read_file(path):
    return FILES.get(path)
