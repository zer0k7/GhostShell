# GhostShell — real attacker data plan (DRAFT, not committed)

Prepared 25 Nov 2026, evening. Answers Salik's question: "will anyone take me if I put
GhostShell on my resume?" — as it stands, no real attacker data and the AI shell was
never tested with Ollama running. This plan fixes both, in ~2 weeks on a throwaway VPS.

## The fix, in one line
Deploy GhostShell on a cheap VPS for 2 weeks, let the real internet attack it, then
write up what actually happened. That turns "basic Python code" into:
"Ran a deception platform on the public internet, captured N real attacks in 2 weeks."

## Cheapest VPS that actually fits (checked 25 Nov 2026)
- **Hetzner CX22 — €3.79/mo (~$4.15, ~Rs 360/mo), 2 vCPU / 4 GB RAM / 40 GB NVMe.**
  Best pick. 4 GB RAM fits Ollama llama3.2:1b (~1.3 GB model) + GhostShell.
  2 weeks costs ~Rs 180. Prices from 2026 VPS comparisons (dev.to, selfhostsetup.com,
  digitallab247.com — all list CX22 at €3.79/mo).
- DigitalOcean $4/mo droplet is only 1 vCPU / 512 MB — too small for Ollama.
  Vultr $5/mo is 1 vCPU / 1 GB — tight for Ollama. Skip both if the AI shell matters.
- Hetzner needs a card and may ask for ID verification — not confirmed for Salik.
  If Hetzner blocks him, fall back to Vultr $5/mo and run WITHOUT Ollama first.

## Safety — read this before any VPS (real catch found 25 Nov)
`config.yaml` sets `host: "0.0.0.0"` and `dashboard.py` / `services.py` bind to that
host. On a VPS that means the dashboard (:5000) and fake admin panel (:8081) would be
public by default — the README's "never expose" line would be broken.
Before deploying, do ALL of these:
1. On the VPS, run UFW: allow only 22 (real SSH, key-only, no password) and 2222
   (the honeypot). Deny 5000 and 8081 from the internet.
2. Access the dashboard only via SSH tunnel from his laptop
   (`ssh -L 5000:localhost:5000 <vps>`), never open it publicly.
3. Throwaway VPS only — nothing real on it, no real keys, no real data.
   Fake secrets only, exactly as in the repo. Destroy the VPS after the 2 weeks.
4. Keep the honeypot on port 2222 (bots scan all ports anyway). Do NOT move it to 22 —
   that would clash with real SSH admin access.
5. The fake AWS metadata / honeytokens are fake by design — that is the point.
   Never put a real AWS key or real credential anywhere near it.

## Steps (about 1 evening to set up)
1. Create Hetzner CX22, Ubuntu 22.04/24.04. SSH in with a key.
2. `git clone https://github.com/zer0k7/GhostShell.git`, install requirements, run it.
3. Apply the firewall rules above. Verify from his laptop: 2222 answers, 5000/8081
   do NOT answer from the internet.
4. Optional, same evening: install Ollama, `ollama pull llama3.2:1b`, then attack the
   honeypot with weird commands (not just `ls`/`cat`) and check the shell answers
   like real Linux. This is the test that was never done — if it fails, the README
   must NOT claim an "AI fake shell" until it passes.
5. Leave it running 14 days. Check the dashboard every 2–3 days via SSH tunnel.
6. Export the data: sessions, top passwords tried, top IPs/countries, bot vs human,
   MITRE tactics seen, honeytoken hits, Sigma rules generated.
7. Write it up (1 page in README + a short post): numbers first, no hype.
   Then destroy the VPS.

## What "good enough for the resume" looks like after this
- Honest line: "Deployed GhostShell on a public VPS for 2 weeks; captured [N] real
  SSH attacks from [N] IPs, profiled bot vs human attackers, mapped [N] MITRE
  techniques, generated Sigma/Suricata rules from live sessions."
- Only claim the AI shell if step 4 actually passed with Ollama running.
- If the numbers are small (e.g. <50 sessions), say so honestly — small real data
  still beats lab-only data, and interviewers can tell the difference.

## Open / unverified
- Hetzner account + card/ID check for Salik in India — not verified.
- No VPS has been created and nothing has been deployed. This is a plan only.
- Ollama on CX22 (4 GB RAM) should fit llama3.2:1b, but was not tested here —
  Ollama is not installed on this machine.
