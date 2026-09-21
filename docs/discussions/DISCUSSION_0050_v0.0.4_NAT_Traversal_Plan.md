# DISCUSSION_0050 — v0.0.4 NAT Traversal Plan (STUN → UDP Hole Punch → Relay → ICE-Lite)

**Status:** OPEN (phase new, baselined 2026-02 from DISCUSSIONS 0042/0045)  
**Target:** v0.0.4  
**Parent:** v0.0.3 — CLOSED 12/12 (DISCUSSION_0045, GAP-001..012 DONE, HEAD `b829ff7`)  
**Date:** 2026-09-21  
**Ground truth:** DISCUSSION_0042 §3 (N1–N5) + DISCUSSION_0045 §6/§9

---

## 1. Do-Not-Mix Note

v0.0.4 là phase tiếp theo của roadmap. v0.0.3 đã khép (GAP-001..012 DONE) — **không mix** feature mới vào v0.0.3.

Trích nguyên văn 0045:11:

> v0.0.3 không thêm network feature (STUN, ICE, relay, hole punch).

Trích nguyên văn 0045:260:

> Lý do: STUN/ICE là feature mới — nên để v0.0.4. v0.0.3 là verify core đã ổn định trên máy thật trước khi mở rộng network capability.

---

## 2. Scope (nguyên văn 0045:200-204)

Trích nguyên văn từ DISCUSSION_0045 §6 (Roadmap Mới), lines 0045:200-204:

```
v0.0.4       Network capability
               ├── STUN client + mapped address
               ├── UDP hole punch
               ├── ICE Lite (host → STUN → relay)
               └── Relay forward-only
```

---

## 3. Work Items N1..N5 (baseline từ DISCUSSION_0042 §3)

Các task dưới đây copy nguyên văn từ 0042 §3. Trạng thái mặc định `[ ]` (OPEN, chưa làm).

| Ma | Ten item | Loai | Mo ta (tasks — nguyên văn 0042 §3) | Trang thai | Depends | Nguon file:dong |
|----|----------|------|--------------------------------------|-----------|---------|-----------------|
| **N1** | STUN Client & Mapped Address Discovery | STUN client (RFC 5389) | N1.1 — Implement STUN binding request/response (RFC 5389 §6)<br>N1.2 — Integrate into daemon startup — run before joining mesh<br>N1.3 — Store mapped address alongside physical address in membership table<br>N1.4 — Configurable STUN server (default: `stun.l.google.com:19302`)<br>N1.5 — Retry on failure (3 attempts, 2s timeout)<br>N1.6 — Add `PCT-024: STUN binding` test<br>N1.7 — Add STUN metric: `smo_stun_latency_seconds` | [ ] | none | 0042:139-153 (tasks 146-152) *(rebaseline: 147-153 → 146-152)* |
| **N2** | UDP Hole Punch (Heartbeat & Gossip) | UDP hole-punch | N2.1 — Implement UDP hole punch protocol (predictable port pairs)<br>N2.2 — Wire into HeartbeatService — try direct UDP first, fall back to relay<br>N2.3 — Wire into GossipEngine — fanout to both physical + mapped addresses<br>N2.4 — Add `smo_hole_punch_success_total` / `smo_hole_punch_failure_total` metrics<br>N2.5 — Integration test: 2 NAT nodes → UDP hole punch → heartbeat ←→ OK<br>N2.6 — Add `PCT-025: UDP hole punch` test | [ ] | N1 | 0042:156-168 (tasks 163-168) |
| **N3** | Relay Service (TURN-Lite) | relay/TURN | N3.1 — Add `RelayService` — allocates per-peer relay sessions<br>N3.2 — Relay protocol: forward encrypted frames (no decrypt), preserve AEAD<br>N3.3 — Auto-detect relay candidates: nodes with `relay: true` capability<br>N3.4 — Bandwidth budget: 1 Mbps per peer, configurable<br>N3.5 — Add `smo_relay_bytes_total` / `smo_relay_active_peers` metrics<br>N3.6 — Integration test: 2 symmetric NAT nodes → relay → gossip ←→ OK | [ ] | none | 0042:172-185 (tasks 179-184) |
| **N4** | ICE-Lite Candidate Gathering & Checks | ICE-lite (không full RFC 8445) | N4.1 — Define `Candidate` struct: (type, addr, port, priority, foundation)<br>N4.2 — Candidate gathering: host addr → STUN mapped → relay (if available)<br>N4.3 — Exchange candidates via existing CBOR protocol during Join<br>N4.4 — Connectivity checks: STUN-style binding requests between candidates<br>N4.5 — Nominate best candidate pair (lowest RTT wins)<br>N4.6 — Add `PCT-026: ICE candidate exchange` test | [ ] | N1, N3 | 0042:188-200 (tasks 195-200) |
| **N5** | 3-Node WAN Test Suite (1 Public, 2 NAT) | auto-discovery / WAN test / mesh NAT mode | N5.1 — Define WAN test topology (docker-compose + iptables NAT simulation)<br>N5.2 — Simulate NAT: `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`<br>N5.3 — Simulate CGNAT: no port forwarding, no UPnP<br>N5.4 — Test case: B & C join via A (outbound TCP) → OK<br>N5.5 — Test case: B ↔ C heartbeat via hole punch → PASS / FAIL log<br>N5.6 — Test case: B ↔ C heartbeat via relay fallback → OK<br>N5.7 — Test case: A crash → B, C detect via heartbeat timeout → DEGRADED<br>N5.8 — Test case: A restart → B, C re-establish → state sync via anti-entropy<br>N5.9 — Add `smo_nat_test_status` metric (0 = unknown, 1 = direct, 2 = relay, 3 = blocked)<br>N5.10 — WAN test suite in CI (weekly, not per-PR — too slow) | [ ] | N1–N4 | 0042:204-226 (tasks 217-226) |

---

## 4. Roadmap / Mở rộng (deferred beyond v0.0.4)

Không xóa. Các mục sau thuộc **N10 — v0.0.4 Preview: Advanced Runtime** (0042:298-306), mang tính gợi ý cho tương lai, **không phải scope hiện tại của v0.0.4**:

- Full ICE (RFC 8445) with TURN
- Mesh federation (cross-mesh routing)
- Smart contract SDK (SMIR → WASM)
- Performance benchmarks as CI gates

---

## 5. Do-not-mix / Packaging (track riêng, song song — không block NAT)

Packaging (RPM/DEB/Docker) là track riêng chạy song song, **không block NAT** v0.0.4. Các mục packaging vẫn còn `[ ]` OPEN (chưa hoàn thành từ v0.0.3) — ghi nhận như vậy, không tác động:

- 0045:122-123 — `[ ]` D.9 DEB package (đã có từ v0.0.2, cần update), `[ ]` D.10 RPM package cho Fedora/RHEL
- 0045:244 — `[ ]` DEB, RPM, Docker image (Success Criteria)
- 0045:286-287 — `❌ Pending` RPM package; `❌ Pending` Docker image (Progress Tracking)
- 0045_3Node:204-205 — `Not implemented (P2)` RPM package (Fedora/RHEL); Docker image
- 0045_3Node:278 — `[ ]` DEB + RPM + Docker packages published (Success Criteria)

---

## 6. Footer

Baselined from DISCUSSION_0042 §N1-N5 + DISCUSSION_0045 §2.6.

**Ground truth:** BẤT KỲ thay đổi item nào phải sửa cả file này + nguồn (0042 §3, 0045 §2.6/§6).