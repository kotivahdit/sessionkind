"""Kotivahdit session-operator detector.

Given a shell/SSH session (timestamped commands + a few connection hints),
estimate whether the operator is a **human**, an automated **script/bot**, or
an **LLM-driven agent** – from passive behavioural signals only. No interaction
with the attacker, no code execution. Pure standard library.

It also raises orthogonal *flags* (e.g. a tool probing whether the host is an
LLM honeypot, or credential reconnaissance) that are independent of the kind.

Entry point: classify().  This is a heuristic, explainable baseline (v0.1),
not a trained model; every verdict lists the signals behind it.
"""
from __future__ import annotations
import re, statistics
from dataclasses import dataclass, field

# --- signal patterns (derived from real honeypot captures) --------------------

# A tool prints a unique marker after each command so a *program* can parse where
# one command's output ends. Humans never do this.
RE_DONE_MARKER = re.compile(r"(___[A-Z]+___)|(__[A-Za-z0-9]+_[a-z0-9_]+_DONE__)"
                            r"|(echo\s+[A-Z0-9_]*DONE[A-Z0-9_]*)")

# Deterministic self-check battery a tool runs to decide whether the host is a
# real shell or an LLM emulation (arithmetic it can verify, pid consistency, ...).
# This identifies a *honeypot-fingerprinting tool*, not necessarily an LLM operator.
RE_PROBE = re.compile(r"check_[0-9a-f]{12,}_|_small_(control|math|pid|done)\b"
                      r"|printf\s+'\\n%s\|%s\\n'|\$\(\(\s*\d+\s*[*+]\s*\d+")

# Mirai / telnet bot fixed escalation sequence.
BOT_SEQUENCE = ("enable", "system", "shell", "sh", "linuxshell", "/bin/busybox",
                "ping;", "ping ;", "cat /proc/mounts")

HUMAN_INTERACTIVE = {"ls", "cd", "pwd", "whoami", "id", "uname", "cat", "ps",
                     "top", "history", "w", "who", "clear", "exit", "ll", "dir"}

RE_RECON_TARGET = re.compile(r"\.kube|kubeconfig|\.aws|\.oci|credentials|rclone\.conf"
                             r"|restic|borg|id_rsa|\.ssh/|\.env\b|secrets?\b"
                             r"|/root/\.|getent\s+passwd|/etc/shadow", re.I)
RE_ERRGUARD = re.compile(r"2>/dev/null|\|\|\s*(true|echo|cat|yum|apt|command)|&>\s*/dev/null")

RE_LIB_CLIENT = re.compile(r"paramiko|libssh2?|asyncssh|-Go\b|_Go\b|golang|russh|"
                           r"jsch|ssh2|go-?ssh|zgrab|nmap|masscan", re.I)
RE_INTERACTIVE_CLIENT = re.compile(r"OpenSSH|PuTTY|Termius|WinSCP|SecureCRT|"
                                   r"MobaXterm|Bitvise|KiTTY", re.I)

KINDS = ("human", "script", "llm-agent")


@dataclass
class Signal:
    name: str
    kind: str
    weight: float
    detail: str = ""


@dataclass
class Verdict:
    kind: str
    confidence: float
    scores: dict
    signals: list = field(default_factory=list)
    flags: list = field(default_factory=list)   # orthogonal observations

    def __str__(self):
        s = ", ".join(f"{k}={v:.2f}" for k, v in self.scores.items())
        fl = ("  flags: " + ", ".join(self.flags)) if self.flags else ""
        top = "\n".join(f"    [{sg.kind:9}] {sg.name}: {sg.detail}" for sg in self.signals)
        return f"{self.kind} (confidence {self.confidence:.2f})  [{s}]{fl}\n{top}"


def _norm_cmd(c):
    c = c.lower()
    c = re.sub(r"[0-9a-f]{12,}", "H", c)          # hashes
    c = re.sub(r"\d+", "N", c)                     # numbers
    return re.sub(r"\s+", " ", c).strip()


def _intervals(ts):
    return [b - a for a, b in zip(ts, ts[1:]) if b >= a]


def classify(commands, client_version=None, pty=None, pty_size=None, duration=None):
    """commands: list of (unix_ts, command_str) OR list of command_str."""
    cmds, ts = [], []
    for c in commands:
        if isinstance(c, (tuple, list)) and len(c) == 2:
            ts.append(float(c[0])); cmds.append(str(c[1]))
        else:
            cmds.append(str(c))
    n = len(cmds)
    text = "\n".join(cmds)
    sig: list[Signal] = []
    flags: list[str] = []
    score = {k: 0.0 for k in KINDS}

    # command variety: a deterministic tool repeats templates (low uniqueness);
    # an LLM agent varies commands based on what it sees (high uniqueness).
    nonempty = [c for c in cmds if c.strip()]
    uniq = (len(set(_norm_cmd(c) for c in nonempty)) / len(nonempty)) if nonempty else 0.0
    is_library = bool(client_version and RE_LIB_CLIENT.search(client_version))

    # 22.11.: the same few commands repeated many times = a polling bot (seen: Go clients
    # re-running `uname` thousands of times on an LLM honeypot). Short != hand-typed.
    if len(nonempty) >= 10 and uniq < 0.2:
        score["script"] += 2.5
        sig.append(Signal("repetitive-polling", "script", 2.5,
                          f"{len(nonempty)} commands but only {uniq:.0%} distinct"))

    n_done = len(RE_DONE_MARKER.findall(text))
    n_probe = len(RE_PROBE.findall(text))
    recon = sum(1 for c in cmds if RE_RECON_TARGET.search(c))
    guarded = sum(1 for c in cmds if RE_ERRGUARD.search(c))

    # ---- honeypot-fingerprinting probe battery => a TOOL (deterministic) ----
    probe_cmds = sum(1 for c in cmds if RE_PROBE.search(c))
    probe_frac = probe_cmds / max(1, len(nonempty))
    if n_probe >= 3:
        flags.append("honeypot-fingerprinting")
        if probe_frac >= 0.4:               # the session *is* a probe tool
            w = min(3.0, 1.6 + probe_cmds * 0.05)
            score["script"] += w
            sig.append(Signal("fingerprint-probe-tool", "script", round(w, 2),
                              f"{probe_cmds} LLM-honeypot probes ({probe_frac:.0%} of session)"))
        else:                               # probes embedded in otherwise varied work
            score["llm-agent"] += 0.8
            sig.append(Signal("fingerprint-probe-embedded", "llm-agent", 0.8,
                              f"{probe_cmds} probes within varied commands"))

    # ---- per-command done markers => LLM/automation framing ----
    if n_done:
        # strong only when commands are varied (adaptive), weak if templated
        base = min(4.0, 1.5 + n_done * 0.5)
        w = base * (0.4 + 0.6 * min(1.0, uniq / 0.6))
        score["llm-agent"] += w
        sig.append(Signal("output-markers", "llm-agent", round(w, 2),
                          f"{n_done} per-command done markers (uniq {uniq:.2f})"))

    # ---- adaptive credential/secret reconnaissance ----
    if recon >= 2 and guarded >= 2:
        flags.append("reconnaissance")
        if uniq >= 0.5:
            w = min(2.5, 0.8 + recon * 0.2)
            score["llm-agent"] += w
            sig.append(Signal("adaptive-recon", "llm-agent", round(w, 2),
                              f"{recon} secret targets, {guarded} error-guarded, varied"))
        else:
            score["script"] += 0.8
            sig.append(Signal("scripted-recon", "script", 0.8,
                              f"{recon} secret targets but templated (uniq {uniq:.2f})"))

    long_one = sum(1 for c in cmds if len(c) > 150)
    if long_one and n_done == 0 and n_probe == 0:
        w = min(1.3, long_one * 0.35)
        score["script"] += w
        sig.append(Signal("long-oneliners", "script", round(w, 2),
                          f"{long_one} commands >150 chars"))

    botlike = sum(1 for c in cmds if any(c.strip().startswith(b) for b in BOT_SEQUENCE))
    if botlike >= 3 and botlike >= 0.6 * max(1, n):
        score["script"] += 2.5
        sig.append(Signal("fixed-bot-sequence", "script", 2.5,
                          "canonical Mirai/telnet escalation"))

    interactive = sum(1 for c in cmds if c.strip()
                      and c.strip().split(" ")[0] in HUMAN_INTERACTIVE and len(c) < 40)
    if interactive >= 2 and n_done == 0 and n_probe == 0 and uniq >= 0.5 and not is_library:
        w = min(2.0, interactive * 0.5)
        score["human"] += w
        sig.append(Signal("interactive-commands", "human", round(w, 2),
                          f"{interactive} short hand-typed commands"))

    typos = sum(1 for c in cmds if re.search(r"\b(sl|cd\.\.|gerp|whaomi|pdw|claer|"
                                             r"cta|mrkdir|chmdo|lls|sudp)\b", c))
    if typos:
        score["human"] += min(1.5, typos * 0.7)
        sig.append(Signal("typos", "human", min(1.5, typos * 0.7),
                          f"{typos} likely typo(s)"))

    if client_version:
        if is_library:
            score["script"] += 0.7; score["llm-agent"] += 0.5
            sig.append(Signal("library-client", "script", 0.7,
                              f"automation client: {client_version}"))
        elif RE_INTERACTIVE_CLIENT.search(client_version):
            score["human"] += 1.0
            sig.append(Signal("interactive-client", "human", 1.0,
                              f"interactive client: {client_version}"))

    if pty and pty_size:
        m = re.match(r"(\d+)x(\d+)", str(pty_size))
        if m:
            w_, h_ = int(m.group(1)), int(m.group(2))
            if 70 <= w_ <= 250 and 20 <= h_ <= 70 and n_done == 0 and n_probe == 0:
                score["human"] += 0.6
                sig.append(Signal("realistic-pty", "human", 0.6, f"terminal {pty_size}"))
            elif h_ >= 300 or w_ >= 400:
                score["script"] += 0.6
                sig.append(Signal("synthetic-pty", "script", 0.6,
                                  f"terminal {pty_size} (non-human geometry)"))

    iv = _intervals(ts)
    if len(iv) >= 3:
        med = statistics.median(iv); mean = statistics.mean(iv) or 1e-9
        cv = statistics.pstdev(iv) / mean
        if med < 0.8 and cv < 0.8 and n_done == 0:
            score["script"] += 1.4
            sig.append(Signal("machine-cadence", "script", 1.4,
                              f"median {med:.2f}s, CV {cv:.2f} (uniform sub-second)"))
        elif med >= 1.5 and cv > 0.4 and not is_library:
            w = min(2.0, 0.8 + cv)
            score["human"] += w
            sig.append(Signal("irregular-cadence", "human", round(w, 2),
                              f"median {med:.2f}s, CV {cv:.2f} (human rhythm)"))
        elif med >= 1.5 and cv > 0.4 and is_library:
            sig.append(Signal("slow-but-automated", "script", 0.0,
                              f"slow/irregular timing but library client ({client_version.split('-')[-1]}) — waiting on installs, not a human"))
        if n_done and uniq >= 0.5 and med < 1.5 and sum(1 for x in iv if x > 3.0) >= 1:
            score["llm-agent"] += 0.8
            sig.append(Signal("burst-then-think", "llm-agent", 0.8,
                              "fast bursts with reasoning gaps"))

    total = sum(score.values())
    if total <= 0:
        return Verdict("unknown", 0.0, {k: 0.0 for k in KINDS}, sig, flags)
    norm = {k: round(v / total, 3) for k, v in score.items()}
    kind = max(norm, key=norm.get)
    ordered = sorted(norm.values(), reverse=True)
    margin = ordered[0] - (ordered[1] if len(ordered) > 1 else 0)
    conf = round(min(0.98, norm[kind] * 0.6 + margin * 0.4 + min(0.2, total / 20)), 3)
    if norm[kind] < 0.45:
        kind = "unknown"
    sig.sort(key=lambda s: -s.weight)
    return Verdict(kind, conf, norm, sig, flags)
