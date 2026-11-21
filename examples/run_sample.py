"""Run sessionkind on the bundled sample sessions (no honeypot needed)."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sessionkind import classify

data = json.load(open(os.path.join(os.path.dirname(__file__), "sample_sessions.json")))
for s in data:
    v = classify(s["commands"], s.get("client_version"), s.get("pty"), s.get("pty_size"))
    print(f"\n# expected: {s['label_guess']}")
    print(v)
