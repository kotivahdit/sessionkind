"""Read Cowrie JSON logs into sessions ready for sessionkind.classify()."""
from __future__ import annotations
import json, glob, datetime as dt
from collections import defaultdict


def _ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def sessions_from_cowrie(paths):
    """paths: a glob string or list of file paths. Yields dicts with keys
    accepted by classify(): session, src_ip, commands, client_version, pty, pty_size, duration."""
    if isinstance(paths, str):
        files = sorted(glob.glob(paths))
    else:
        files = list(paths)
    S = defaultdict(lambda: {"src_ip": None, "client_version": None, "pty": False,
                             "pty_size": None, "commands": [], "t0": None, "t1": None})
    for f in files:
        op = open(f, "rb")
        for raw in op:
            try:
                e = json.loads(raw)
            except Exception:
                continue
            sid = e.get("session")
            if not sid:
                continue
            s = S[sid]
            try:
                t = _ts(e["timestamp"])
            except Exception:
                t = None
            if t is not None:
                s["t0"] = t if s["t0"] is None else s["t0"]; s["t1"] = t
            s["src_ip"] = e.get("src_ip", s["src_ip"])
            ei = e.get("eventid", "")
            if ei == "cowrie.client.version":
                s["client_version"] = e.get("version")
            elif ei == "cowrie.client.size":
                s["pty"] = True
                s["pty_size"] = f'{e.get("width")}x{e.get("height")}'
            elif ei == "cowrie.command.input" and t is not None:
                s["commands"].append((t, e.get("input", "")))
    for sid, s in S.items():
        yield {"session": sid, "src_ip": s["src_ip"],
               "commands": s["commands"], "client_version": s["client_version"],
               "pty": s["pty"], "pty_size": s["pty_size"],
               "duration": (s["t1"] - s["t0"]) if s["t0"] and s["t1"] else None}
