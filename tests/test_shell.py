"""Tests for the stateful fake shell — run with: python -m pytest tests/"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ghostshell import db
from ghostshell.shell import FakeShell


def _shell(tmp_path):
    db_path = str(tmp_path / "t.db")
    db.init_db(db_path)
    return FakeShell({}, db_path, 1, "127.0.0.1", "admin")


def test_stateful_fs_mkdir_echo_cat(tmp_path):
    sh = _shell(tmp_path)
    assert sh.handle("mkdir /home/admin/evil")[0] == ""
    assert sh.handle("echo pwned > /home/admin/evil/note.txt") == ("", False)
    out, _ = sh.handle("cat /home/admin/evil/note.txt")
    assert out.strip() == "pwned"
    out, _ = sh.handle("ls /home/admin/evil")
    assert "note.txt" in out


def test_touch_and_rm(tmp_path):
    sh = _shell(tmp_path)
    sh.handle("touch /home/admin/x.txt")
    out, _ = sh.handle("ls")
    assert "x.txt" in out
    sh.handle("rm /home/admin/x.txt")
    out, _ = sh.handle("ls")
    assert "x.txt" not in out


def test_honeytoken_still_there(tmp_path):
    sh = _shell(tmp_path)
    out, _ = sh.handle("cat aws_credentials.txt")
    assert "AKIAIOSFODNN7FAKEKEY" in out


def test_sessions_isolated(tmp_path):
    a = _shell(tmp_path)
    b = _shell(tmp_path)
    a.handle("mkdir /home/admin/only-a")
    out, _ = b.handle("ls")
    assert "only-a" not in out
