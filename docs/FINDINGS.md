# Field note: what sessionkind sees in real honeypot traffic

*Kotivahdit, 2026-11-22. Data: ~5 days of one SSH/Telnet honeypot, 1,304 sessions with ≥2 commands. These are the tool's own classifications, not ground truth — read the limitations in the [README](../README.md).*

Two observations stood out, and together they are a small, concrete picture of how LLMs are showing up on both sides of a honeypot.

## 1. An LLM-agent-style operator doing credential reconnaissance

A single source (`5.231.221.23`, a German reseller host) ran, across several short sessions over a paramiko connection, a sequence like:

```
id; hostname; uname -a
echo ___CMDDONE___$?
cat /root/.kube/config 2>/dev/null; ls -la /root/.aws 2>/dev/null
echo ___CMDDONE___$?
find / -xdev \( -name 'rclone.conf' -o -name '.env' \) 2>/dev/null | head
echo ___CMDDONE___$?
getent passwd | awk -F: '$3>=1000{print $1}'; grep -vE '^[^:]+:[!*]' /etc/shadow 2>/dev/null
```

Every command is followed by a unique `___CMDDONE___` marker so a *program* can tell where each command's output ends — and the commands are **varied and adaptive**, each hunting a different class of secret (Kubernetes, AWS, rclone/restic, shadow). sessionkind labels this `llm-agent` at **0.90** with a `reconnaissance` flag. A fixed script does not improvise recon like this; a human does not frame every command with a parser token.

## 2. A tool fingerprinting us *as* an LLM honeypot

Separately, a `/24` block (`195.178.110.x`) accounted for most of the `honeypot-fingerprinting` flags (1,220 sessions). It ran a deterministic self-check battery:

```
printf '\n%s|%s\n' 'check_<hash>_small_control' 'check_<hash>_small_control'
printf '\n%s|%s\n' 'check_<hash>_small_math'    "$((226*827+13))"
printf '\n%s|%s\n' 'check_<hash>_small_pid'     "$$"
```

This is the mirror image of finding 1: an attacker's tooling testing whether the *host* is a real shell or an LLM emulation — arithmetic it can verify, a stable PID, positional-argument and shell-function round-trips. It is exactly the fingerprinting described in the honeypots-and-LLMs survey ([SoK, arXiv:2510.25939](https://arxiv.org/abs/2510.25939)). Because it is deterministic and repetitive, sessionkind correctly keeps it in `script` (a tool), not `llm-agent`, while raising the flag.

## Why this matters

Everything else — the other ~1,260 sessions — was ordinary bot noise (Mirai-style telnet escalation, library-client droppers) and a handful of plausibly human sessions. The LLM signals are **rare**, which is the point: a detector that called everything an "AI attack" would be useless and dishonest. The value is isolating the few sessions worth a human's attention.

This is also why we keep the honeypot's own LLM shim detection-resistant (see the toolkit's [`llm-shim`](https://github.com/kotivahdit/toolkit)): the same probes in finding 2 are what the shim has to survive.

## Caveats

- One sensor, five days, English-centric tooling. Not a population estimate.
- `5.231.221.23` may be a research scanner or a human driving an agent interactively — we only observe behaviour, not intent.
- IP addresses here are indicators that attacked our sensor; they are public IOCs, not an accusation about whoever currently holds the address.
