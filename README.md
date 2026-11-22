# sessionkind

**Passively tell whether the operator behind an SSH / shell session is a human, a script/bot, or an LLM-driven agent — with an explanation for every verdict.**

A small, dependency-free Python library from the [Kotivahdit](https://kotivahdit.github.io) volunteer honeypot network (Finland). It reads the commands an attacker ran (and a few connection hints) and returns a classification plus the behavioural signals behind it. It never touches the attacker's system and runs no code against them — this is passive triage, not hack-back.

> Status: **v0.2, experimental.** This is an explainable *heuristic baseline*, not a trained model. It is meant to be read, criticised and improved. The signal weights are hand-tuned on real honeypot captures; treat the output as a lead, not proof.

## Why

Automated attacks increasingly include **LLM-driven agents** that reason over command output instead of replaying a fixed script. Recent work studies this from both sides — detecting an attacking agent's model ([Pasquini & Reworr, "Say Shibboleth", arXiv:2611.12386, Nov 2026](https://arxiv.org/abs/2611.12386)) and surveying how honeypots and LLMs fingerprint each other ([SoK, arXiv:2510.25939, 2025](https://arxiv.org/abs/2510.25939)). `sessionkind` is the defender-side, boringly practical companion: given a session you already captured, *which broad category of operator was it?* — so an analyst can triage a honeypot or a compromised host faster.

## Install

```bash
pip install sessionkind      # once published
# or, from a checkout:
pip install .
```

No third-party dependencies; Python 3.9+.

## Use

```python
from sessionkind import classify

v = classify(
    commands=[(0.0, "id; uname -a"),
              (0.2, "echo ___CMDDONE___$?"),
              (0.5, "cat /root/.kube/config 2>/dev/null"),
              (0.7, "echo ___CMDDONE___$?"),
              (1.1, "find / -name rclone.conf 2>/dev/null || true")],
    client_version="SSH-2.0-paramiko_5.1.0",   # optional
    pty=True, pty_size="200x1000",              # optional
)
print(v.kind)        # 'llm-agent'
print(v.confidence)  # 0.0 – 0.98
print(v.flags)       # ['reconnaissance']
print(v)             # full explanation with every signal
```

`commands` is a list of `(unix_timestamp, command_string)` tuples, or just command strings (you then lose the timing signals). Everything else is optional.

### Honeypot logs

```bash
python -m sessionkind.cli /path/to/cowrie.json*                 # Cowrie
python -m sessionkind.cli --beelzebub /path/to/beelzebub.json   # Beelzebub (LLM honeypot)
```

Reads [Cowrie](https://github.com/cowrie/cowrie) or [Beelzebub](https://github.com/mariocandela/beelzebub) JSON logs, classifies each session and prints a summary. Beelzebub runs many commands as separate *inline* (exec) sessions; these are regrouped per source IP (gap < 5 min).

## What it returns

`classify()` returns a `Verdict`:

| field | meaning |
|---|---|
| `kind` | `human`, `script`, `llm-agent`, or `unknown` |
| `confidence` | 0–0.98 |
| `scores` | normalised score per kind |
| `signals` | the weighted behavioural signals behind the verdict |
| `flags` | orthogonal observations, independent of kind: `honeypot-fingerprinting` (a tool probing whether the host is an LLM honeypot), `reconnaissance` (credential/secret hunting) |

### Signals it looks at

- **LLM / automation framing** — a per-command "done" marker so a *program* can parse output boundaries (`echo ___CMDDONE___$?`); deterministic self-check batteries (`check_<hash>_small_math`, `$((226*827+13))`, `$$`) that tools use to decide whether a shell is real or an LLM emulation.
- **Adaptive vs. templated** — command *variety*. A deterministic tool repeats templates (low variety → script); an LLM agent varies commands based on what it just saw (high variety).
- **Reconnaissance** — error-guarded hunting for cloud/credential material (`.kube`, `.aws`, `rclone.conf`, `/etc/shadow`).
- **Bot fingerprints** — the canonical Mirai/telnet `enable → system → shell → sh → /bin/busybox` escalation.
- **Human tells** — short interactive commands, typos, an interactive client banner (OpenSSH/PuTTY), a plausible terminal size, and an irregular typing rhythm.
- **Timing** — uniform sub-second cadence (machine) vs. irregular multi-second gaps (human). A library client (paramiko/Go) can fake slow timing while waiting on `apt-get`, so slow timing alone never makes something "human".

## Validated on real data

Run against this network's own honeypots (sessions with ≥2 commands, November 2026):

| kind | Cowrie SSH/Telnet (~6 days) | Beelzebub LLM honeypot (~1 day) |
|---|---:|---:|
| script / bot | 1,551 (40 IPs) | 379 (32 IPs) |
| unknown | 21 (5 IPs) | 0 |
| human | 4 (4 IPs) | 0 |
| **llm-agent** | **8 (1 IP)** | 0 |

Most Beelzebub traffic is honeypot-fingerprinting probe tools and bots polling the same command thousands of times — exactly what an LLM honeypot attracts.

See **[docs/FINDINGS.md](docs/FINDINGS.md)** for the two observations behind these numbers (an LLM-agent doing credential recon, and a tool fingerprinting us *as* an LLM honeypot).

The one `llm-agent` IP ran adaptive, error-guarded credential reconnaissance with per-command done markers over a paramiko connection — classified `llm-agent` at 0.90. That is the kind of rare, specific lead the tool is for; it is deliberately **not** a label it hands out freely.

## Limitations — please read

- **Heuristic, not ground truth.** We cannot know the true operator for most sessions, so these numbers are the tool's own output, not a measured accuracy. Treat a verdict as a lead to investigate.
- **A skilled human can look like a script, and a careful agent can hide.** Low-interaction honeypots also see fewer commands, which weakens every signal.
- **`llm-agent` ≠ "a specific model".** This tells you the *behaviour* looks agent-driven; it does not identify a vendor or model.
- **Short sessions are unreliable.** With 2–3 commands there is little to go on; such sessions often fall to `unknown`.
- English-centric command set; tuned on one network's traffic. Contributions with counter-examples are very welcome.

## Contributing

Issues and PRs welcome, especially: sessions the tool gets wrong, new signals, and adapters for other honeypots (not just Cowrie). Please do not include real attacker payloads that execute; sanitise before sharing.

## License

Apache-2.0 · Kotivahdit, kotivahdit@proton.me · part of the [Kotivahdit toolkit](https://github.com/kotivahdit/toolkit)
