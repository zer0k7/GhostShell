"""Tests for the attack-chain profiler."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ghostshell.profiler import profile_commands


def test_chain_recon_to_privesc():
    p = profile_commands(["whoami", "ps aux", "sudo -l", "crontab -l"])
    assert "Recon to privesc — attacker is escalating" in p["chains"]
    assert "Privilege Escalation" in p["tactics"]


def test_bot_scores_low():
    p = profile_commands(["ls", "pwd"])
    assert p["chains"] == []
    assert p["level"].startswith("basic")


def test_full_kill_chain():
    p = profile_commands(["nmap -sV 10.0.0.1", "sudo su", "crontab -e", "cat /etc/shadow"])
    assert any("Full kill chain" in c for c in p["chains"])
