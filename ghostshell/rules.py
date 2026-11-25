"""Turn captured attacks into defence (Week 4 core, Week 1 skeleton).

Given an attacker's IP and commands, generate a Sigma rule and a
Suricata rule. These are real, usable outputs — not placeholders.
"""


def sigma_rule(src_ip, commands, rule_id="GS-001"):
    cmds = " OR ".join(f'"{c}"' for c in commands[:5]) or '"*"'
    return f"""title: GhostShell — suspicious activity from honeypot attacker {src_ip}
id: {rule_id}
status: experimental
description: Commands observed from an attacker on the GhostShell honeypot.
logsource:
    product: linux
    service: sshd
detection:
    selection:
        src_ip: '{src_ip}'
        CommandLine|contains:
            - {cmds}
    condition: selection
level: high
tags:
    - attack.execution
"""


def suricata_rule(src_ip, sid=1000001):
    return (
        f'alert tcp {src_ip} any -> $HOME_NET 22 '
        f'(msg:"GhostShell honeypot attacker {src_ip}"; '
        f'sid:{sid}; rev:1; classtype:attempted-admin;)\n'
    )


def blocklist_entry(src_ip):
    return src_ip
