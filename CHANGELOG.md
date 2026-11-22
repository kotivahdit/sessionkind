# Changelog

## 0.2.0 – 2026-11-22
- Beelzebub (LLM honeypot) log reader; inline exec sessions regrouped per source IP (`--beelzebub`).
- New signal `repetitive-polling`: many commands but few distinct ones ⇒ script (bots re-running `uname` thousands of times).
- Short commands from a library client (paramiko/Go) no longer count as "hand-typed"; they require command variety.
- Validation table updated with Cowrie + Beelzebub data.

## 0.1.0 – 2026-11-22
- First release: explainable human / script / LLM-agent classifier, Cowrie reader, CLI, examples, field note.
