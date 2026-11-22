"""Read Beelzebub (LLM honeypot) JSON logs into sessions for sessionkind.classify().

Beelzebub logs interactive SSH sessions with a session id, but many tools run each
command as a separate *inline* (exec) session. By default those are regrouped per
source IP: inline commands from the same IP with gaps < `gap` seconds form one session.
"""
from __future__ import annotations
import datetime as dt, json, glob
from collections import defaultdict


def _ts(s):
    s = s.replace("Z", "+00:00")
    if "." in s:  # trim nanoseconds to microseconds for fromisoformat
        head, tail = s.split(".", 1)
        frac, tz = (tail[:-6], tail[-6:]) if tail[-6] in "+-" else (tail, "")
        s = f"{head}.{frac[:6]}{tz}"
    return dt.datetime.fromisoformat(s).timestamp()


def sessions_from_beelzebub(paths, group_inline=True, gap=300.0):
    files = sorted(glob.glob(paths)) if isinstance(paths, str) else list(paths)
    clients = {}                         # src_ip -> last seen SSH client banner
    interactive = defaultdict(lambda: {"src_ip": None, "commands": []})
    inline = defaultdict(list)           # src_ip -> [(ts, cmd)]
    for f in files:
        for raw in open(f, "rb"):
            try:
                e = json.loads(raw)
            except Exception:
                continue
            ip = e.get("src_ip")
            if not ip:
                continue
            if e.get("client"):
                clients[ip] = e["client"]
            cmd = e.get("input")
            if not cmd or e.get("status") == "End":
                continue
            try:
                t = _ts(e["timestamp"])
            except Exception:
                continue
            msg = (e.get("msg") or e.get("message") or "").lower()
            if "inline" in msg and group_inline:
                inline[ip].append((t, cmd))
            else:
                s = interactive[e.get("session") or f"{ip}-{int(t)}"]
                s["src_ip"] = ip; s["commands"].append((t, cmd))
    for sid, s in interactive.items():
        cmds = sorted(s["commands"])
        yield {"session": sid, "src_ip": s["src_ip"], "commands": cmds,
               "client_version": clients.get(s["src_ip"]), "pty": None, "pty_size": None,
               "duration": cmds[-1][0] - cmds[0][0] if cmds else None}
    for ip, cmds in inline.items():
        cmds.sort()
        cur = []
        for c in cmds:
            if cur and c[0] - cur[-1][0] > gap:
                yield _pack(ip, cur, clients); cur = []
            cur.append(c)
        if cur:
            yield _pack(ip, cur, clients)


def _pack(ip, cmds, clients):
    return {"session": f"{ip}@{int(cmds[0][0])}", "src_ip": ip, "commands": cmds,
            "client_version": clients.get(ip), "pty": None, "pty_size": None,
            "duration": cmds[-1][0] - cmds[0][0]}
