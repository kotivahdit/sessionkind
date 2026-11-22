import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from sessionkind import classify

def seq(cmds, step):
    return [(i*step, c) for i, c in enumerate(cmds)]

def test_mirai_bot():
    v = classify(seq(["enable","system","shell","sh","/bin/busybox MIRAI"], 0.1))
    assert v.kind == "script", v

def test_llm_agent_markers():
    cmds = seq(["id; uname -a","echo ___CMDDONE___$?","cat /root/.kube/config 2>/dev/null",
                "echo ___CMDDONE___$?","find / -name rclone.conf 2>/dev/null || true",
                "echo ___CMDDONE___$?","ls -la /var/backups 2>/dev/null","echo ___CMDDONE___$?"], 0.2)
    v = classify(cmds, client_version="SSH-2.0-paramiko_5.1.0", pty=True, pty_size="200x1000")
    assert v.kind == "llm-agent", v
    assert "reconnaissance" in v.flags, v

def test_human():
    cmds = [(0,"ls -la"),(3.2,"cd /var/www"),(7.9,"cat config.php"),(14.1,"whoami"),(20.3,"ps aux")]
    v = classify(cmds, client_version="SSH-2.0-OpenSSH_9.6", pty=True, pty_size="120x40")
    assert v.kind == "human", v

def test_probe_battery_is_tool():
    h = "b4070af80799b14e3daf39a1065fde72"
    cmds = seq([f"printf '|' 'check_{h}_small_control'",
                f"printf '|' 'check_{h}_small_math' $((2*3))",
                f"printf '|' 'check_{h}_small_pid' $$",
                f"printf '|' 'check_{h}_small_done'"], 0.2)
    v = classify(cmds, client_version="SSH-2.0-Go")
    assert v.kind == "script", v
    assert "honeypot-fingerprinting" in v.flags, v

def test_repetitive_polling_is_script():
    cmds = [(i*5.0, "uname -s -v -n -r -m" if i % 2 == 0 else "uname -m | awk '{printf $1}'") for i in range(40)]
    v = classify(cmds, client_version="SSH-2.0-Go")
    assert v.kind == "script", v


if __name__ == "__main__":
    import traceback
    fns = [f for n,f in sorted(globals().items()) if n.startswith("test_")]
    ok=0
    for f in fns:
        try: f(); print("PASS", f.__name__); ok+=1
        except AssertionError as e: print("FAIL", f.__name__, "->", str(e)[:160])
        except Exception: traceback.print_exc()
    print(f"{ok}/{len(fns)} passed")