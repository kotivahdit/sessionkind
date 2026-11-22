"""sessionkind CLI.  Usage: python -m sessionkind.cli [--beelzebub] <log.json...>   (default format: Cowrie)"""
import sys, collections
from .detect import classify
from .cowrie import sessions_from_cowrie
from .beelzebub import sessions_from_beelzebub


def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__); return 2
    reader = sessions_from_cowrie
    if "--beelzebub" in argv:
        argv = [a for a in argv if a != "--beelzebub"]; reader = sessions_from_beelzebub
    tally = collections.Counter()
    shown = 0
    for s in reader(argv):
        if len(s["commands"]) < 2:
            continue
        v = classify(s["commands"], s["client_version"], s["pty"], s["pty_size"], s["duration"])
        tally[v.kind] += 1
        if v.kind in ("llm-agent", "human") and shown < 20:
            shown += 1
            print(f"\n{s['src_ip']}  session {s['session']}  ({len(s['commands'])} cmds)")
            print("  " + str(v).replace("\n", "\n  "))
    print("\n=== totals ===")
    for k, n in tally.most_common():
        print(f"  {k:10} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
