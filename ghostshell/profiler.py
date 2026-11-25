"""Attacker profiling v2: MITRE mapping + skill scoring + attack chains.

v1 only matched single keywords. v2 also looks at the ORDER of
commands — a real attack is a chain, not a bag of words:
  recon -> privilege escalation -> persistence -> exfiltration
is a very different story from `ls` + `whoami` and then leaving.
"""
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

# ordered tactic sequences that mean a real attack chain
CHAINS = [
    (["Discovery", "Privilege Escalation"], "Recon to privesc — attacker is escalating"),
    (["Discovery", "Credential Access"], "Recon to credential theft"),
    (["Credential Access", "Exfiltration"], "Credential theft to exfiltration"),
    (["Discovery", "Command and Control"], "Recon to payload download"),
    (["Privilege Escalation", "Persistence"], "Privesc to persistence — trying to stay in"),
    (["Discovery", "Privilege Escalation", "Persistence"], "Full kill chain: recon, privesc, persistence"),
    (["Discovery", "Privilege Escalation", "Exfiltration"], "Full kill chain: recon, privesc, exfiltration"),
]


def _tactics_in_order(commands):
    seen = []
    for cmd in commands:
        low = cmd.lower()
        for keyword, (tactic, _) in MITRE_MAP.items():
            if keyword in low and tactic not in seen:
                seen.append(tactic)
    return seen


def profile_commands(commands):
    tactics, techniques = set(), set()
    score = 0
    for cmd in commands:
        low = cmd.lower()
        for keyword, (tactic, technique) in MITRE_MAP.items():
            if keyword in low:
                tactics.add(tactic)
                techniques.add(technique)
                score += 10
        if any(k in low for k in ("sudo", "chmod +s", "/etc/shadow", "nmap -s")):
            score += 15
        if low.startswith(("ls", "pwd", "whoami")):
            score += 2

    ordered = _tactics_in_order(commands)
    chains = []
    for seq, label in CHAINS:
        # seq appears in order inside `ordered`
        idx = 0
        for t in ordered:
            if idx < len(seq) and t == seq[idx]:
                idx += 1
        if idx == len(seq):
            chains.append(label)
            score += 20

    if score >= 80:
        level = "skilled — likely human, targeted"
    elif score >= 40:
        level = "intermediate — probing with intent"
    else:
        level = "basic — likely automated bot / spray"
    return {
        "tactics": sorted(tactics),
        "techniques": sorted(techniques),
        "score": score,
        "level": level,
        "chains": chains,
        "tactic_order": ordered,
    }
