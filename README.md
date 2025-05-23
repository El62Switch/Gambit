Self-Healing SSH Bastion

NVIDIA AgentIQ Hackathon

Overview

Detects SSH attacks, analyzes them with NVIDIA NIM, and intelligently mitigates based on AI-driven decisions.

How It Works





Fail2ban monitors SSH (simulated with manual webhooks due to WSL2 networking limits).



DetectionAgent processes webhooks, asks NIM to analyze the attack (brute-force vs. accidental), and logs a formatted threat report.



NIM decides whether to block the IP with iptables or log it, then restarts SSH if blocked.

Setup





WSL, Python 3.12, Fail2ban



Run: source ~/myenv/bin/activate; python3 detection_agent.py



Webhook: curl -X POST http://localhost:8000/api/topics/fail2ban -H "Content-Type: application/json" -d '{"banned_ip":"192.168.0.1"}'

Files





detection_agent.py: Webhook server with NIM integration



selfheal-mitigate.sh: Mitigation script



mitigation.txt: Threat report log



demo.mp4: Demo video

Notes

WSL2 networking required manual webhooks to simulate Fail2ban bans. NIM’s AI analysis distinguishes malicious brute-force attacks from accidental logins, driving intelligent mitigation decisions.
