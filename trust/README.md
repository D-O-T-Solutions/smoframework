# trust/

Trust and reputation engine. All scores are computed locally per-node.

## Components (§XI)
- Citizen Score     — online time, heartbeat stability, route reliability
- Execution Score   — successful contract completions
- Witness Score     — witness participation and accuracy
- Consistency Score — result agreement with majority

## Modules
- `scoring/`  — Trust score computation
- `decay/`    — Score decay over time (sliding window)
- `store/`    — Trust data persistence
- `exchange/` — Trust digest gossip across mesh
