"""Attacker profiling: MITRE ATT&CK mapping + skill scoring.

Week 3 expands this with LLM intent classification. Week 1 ships
the deterministic rules so every captured command is already tagged.
"""
# command keyword -> (MITRE tactic, technique)
MITRE_MAP = {
    "nmap": ("Discovery", "T1046 Network Service Discovery"),
    "masscan": ("Discovery", "T1046 Network Service Discovery"),
    "whoami": ("Discovery", "T1033 System Owner/User Discovery"),
    "id": ("Discovery", "T1033 System Owner/User Discovery"),
    "uname": ("Discovery", "T1082 System Information Discovery"),
    "ps": ("Discovery", "T1057 Process Discovery"),
    "netstat": ("Discovery", "T1049 System Network Connections Discovery"),
    "cat /etc/passwd": ("Credential Access", "T1003 OS Credential Dumping"),
    "cat /etc/shadow": ("Credential Access", "T1003 OS Credential Dumping"),
    "sudo": ("Privilege Escalation", "T1548 Abuse Elevation Control"),
    "chmod +s": ("Privilege Escalation", "T1548 Abuse Elevation Control"),
    "su ": ("Privilege Escalation", "T1548 Abuse Elevation Control"),
    "curl": ("Command and Control", "T1105 Ingress Tool Transfer"),
    "wget": ("Command and Control", "T1105 Ingress Tool Transfer"),
    "nc ": ("Command and Control", "T1095 Non-Application Layer Protocol"),
    "scp": ("Exfiltration", "T1041 Exfiltration Over C2 Channel"),
    "tar": ("Collection", "T1560 Archive Collected Data"),
    "history": ("Discovery", "T1217 Browser Information Discovery"),
    "crontab": ("Persistence", "T1053 Scheduled Task/Job"),
    "systemctl": ("Persistence", "T1543 Create or Modify System Process"),
    "ssh": ("Lateral Movement", "T1021 Remote Services"),
}


def profile_commands(commands):
    """commands: list of command strings. Returns tactics, techniques, score."""
    tactics, techniques = set(), set()
    score = 0
    for cmd in commands:
        low = cmd.lower()
        for keyword, (tactic, technique) in MITRE_MAP.items():
            if keyword in low:
                tactics.add(tactic)
                techniques.add(technique)
                score += 10
        # skill signals
        if any(k in low for k in ("sudo", "chmod +s", "/etc/shadow", "nmap -s")):
            score += 15
        if low.startswith(("ls", "pwd", "whoami")):
            score += 2
    if score >= 60:
        level = "skilled — likely human, targeted"
    elif score >= 25:
        level = "intermediate — probing with intent"
    else:
        level = "basic — likely automated bot / spray"
    return {
        "tactics": sorted(tactics),
        "techniques": sorted(techniques),
        "score": score,
        "level": level,
    }
