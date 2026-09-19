# DISCUSSION_0048 — Local PQ Handshake Debug (A↔B) Before 3-Node Deployment

**Status:** Planning → Implementation  
**Target:** Verify A↔B PQ handshake on localhost before DISCUSSION_0045 3-node deployment  
**Depends on:** G3 Packet Auth COMPLETED (DISCUSSION_0047 P0–P8)  
**Date:** 2026-09-17

---

## 1. Problem Statement

G3 Packet Authentication (P0–P8) is **complete and tested**: 25/25 ctest, 24/24 PCT.

But **local PQ handshake between Node A and Node B fails** on localhost.

Current failure:
- Node A (port 7777): `PQ handshake failed: connection closed during secure read`
- Node B (port 7778): `Trying endpoint: 127.0.0.1:7777 ... FAIL (recv: read failed during version handshake)`

Both logs indicate the connection dies **before** G3 Packet Authentication is even reached — it fails at the **PQ handshake / version handshake layer**.

---

## 2. Layer Stack (what must work before G3)

```
TCP connection
    ↓
Version handshake (4 bytes each direction)
    ↓
PQ handshake (KEM + certs + signatures)
    ↓
Authenticated SecureSession
    ↓
G3 Packet Authentication (AEAD + replay)
```

**Failure is at layer 2–3**, NOT G3.

---

## 3. Debug Plan: A↔B First, Then C

### Phase 1: A↔B Standalone Debug

**Goal:** Get A (7777) and B (7778) to complete PQ handshake on localhost.

#### 1.1 Isolate version handshake
- Add debug logging in `version_handshake_client` / `version_handshake_server` (core/transport/framing.cpp)
- Verify both sides exchange 4-byte version correctly

#### 1.2 Trace PQ handshake steps
- Client (B) sends: `ClientHello = [pk_len][kem_pk][cert_len][cert][sig]`
- Server (A) responds: `ServerHello = [pk][ct][cert][sig]`
- Client sends: `ClientFinish = [ct_len][ct2]`

Add per-step logging in `SecureSession::client_handshake()` / `server_handshake()` (core/transport/secure_session.cpp)

#### 1.3 Identify who closes connection
- Current logs suggest client (B) closes after `version_handshake_client` fails
- But server (A) says `connection closed during secure read` — indicates client closed before PQ handshake completed
- Need to determine: is it version handshake failure, or client certificate missing, or server cert verification failing?

### Phase 2: Add C Once A↔B Works

Only after A↔B handshake passes, add Node C (7779).

---

## 4. Required Fixes (before testing)

### 4.1 Client (B) needs client cert for mutual auth
- `cli_context.cpp` now loads `node.cert.smoc` + identity secret key ✅
- Verify B actually has valid cert at `/tmp/smo-test/nodeB/node.cert.smoc`

### 4.2 Server (A) needs root pubkey + mesh_id
- `main.cpp` loads `mesh_dir/authority.pub` + extracts mesh_id ✅
- Verify `~/.smo/meshes/testmesh/authority.pub` exists and matches

### 4.3 Remove mesh-dir from B join (use pure join token)
- B should not need `--mesh-dir` — join token contains bootstrap endpoints
- Current B command uses `--join` token only — correct

### 4.4 Mesh JSON advertise address = 127.0.0.1:7777
- Already updated in `~/.smo/meshes/testmesh/mesh.json` ✅

---

## 5. Debug Commands

```bash
# Terminal 1: Start A (authority)
cd /home/nguyenduccanh/shellmap_project/smoframework
./build/cmd/smo-node/smo-node --daemon --port 7777 \
  --data /tmp/smo-test/nodeA \
  --mesh-dir ~/.smo/meshes/testmesh \
  --name "NodeA" > /tmp/nodeA.log 2>&1

# Terminal 2: Start B (join)
JOIN_TOKEN="SMO-JOIN-qQEBAmh0ZXN0bWVzaAMBBAMFgW4xMjcuMC4wLjE6Nzc3NwaiAWlBdXRob3JpdHkCZnNlcnZlcgcaaquZXgh4IDVmMmY2OTJkMTIzMzVmNjEyOTY2Y2JmNDE3MDEwYzhmCXVyb290OjNkMmQ1NTU4NThiMWM5ZTAM7RUm7oudfF6lg0pRGTqpSZLGgGtPqOCciFIHfJIzkMuGeNN0Jfir7IAywJhVTKbG0kUYRfDcEQYeWV41v-O4VTYIPl6XmCBgTpx5wE15rN9ZVqyHllvDN_JEzwueO357FFRCZzSpd7L86J6Aj6kFLADdVyfTV62sBZjkZyJzQoSYT6yNJLOaWg96KE7fg67E71QojCY7XaeaILak1hdnr-lXhGMqZChj35AW00w3jigQQ1wjmeL7cZBM8znXGcSHJa0Jgc5FkGNI3REt7gp6pg0ExywG8o73OBoYLg4mVoe8jUfD2qgqyQ_5Csw4N1z15fv8p17jyc17hYHePr3hT2hpvI5Z7Rr-QivO0RLdWcK-a2IdqruY3y5GOQkk2uT3nPt6V8Ucc8bf3pBHJ9-_jygjs-vD3DBJKo14Fv6jlgcyXRsA58ozlXaktS1iUf6MKrg0WNxWN7Cxs8QmfwrCoGklYN-w8BDzjfGt7E7pq0IcL8epzeTfxsidyiq7DVIc2ey0BKNYKTVvwKinLw-zXT8mDTns5ILWN60k_oTs5iH3Vm2SdG0pv7bVwqlDzacZeFlKwD4-ZBTc4cZYCtsWclQct7ZSKUFlWHooNXRXO9tP1eCkr4yHF2kG9__3OzLD9_QF_0VFM1JN8scdLdGMHZhx_T7tJuAeM_8tE-Lj025dE0J08nU1mNYMfXv0b8Z33wNebPCxYk4-IqK069pF7zatnw0L34uc5BmTnLz8o5WnqZYZgx-DFJ-d4-LEaq3jN04rf5HIcQ34FLD31-ecU6GTHYOHJIKgCtVih23DvjpaEbvQAvsHce9_3BxVfvMwzg4sYZ0YG9S2mmip_BnW3V2Xnl1_WhKlPpCSdAc5mJzNaasdepT_CdKsiuXTaeeK3IQnLysVJaNPfU_hWP07chEO8f1CdK3TFIxoSIrS11_9u8J9L1FKgaSlP6-iLWgW1HK-cZpGv71tq7xhzSA4QJOKxF7D2a4zWYb9ZH7qGj7Amiey2WuoBIJhq2fJpLt1Ru9W1buCaes0uuraIhOR_f5gLtCbII5hOgCcKHReLZ9usa6Lm8bxFP72PgRf1UKE4cQrLlniK13VguDhylCi91KpODS7kGkrb1drieWZ2oSuRbWdOwRIIQG7Nvb3dVqX9O2nIwdhSBMzpfeUAk0OjIKldO3g6gInXbzJa-HwQetXCDAjcq2cBdlYBSddIvy_hbBpJ_Huz9BzzbO77IAozkz1byktOZ22-pFjuIo0UltNvZIecV-Ah2BQIEAnzgISgQk05i8B5uHGCRPa_6kHaF7fy0hCQhjjPqHHYkMBwc_57StSJ1lDPlvBrcApMQqdbSEBuKCyNN6bICtrzVertEuXi3kD88T9ymrIq11qmF3S99CXFOqBSFgpaGIPqsfe6sV_dMAvzwBpupBmGT0TUcZBUtQB7TChm5cWbISBv8hJyPWA1AorN3mD2DBTv-EiRWYwDvDvGlDG0_OzkBGvmwVXrV2yF9qLZ7VckoPWSiEZE7xL2WSNRgVOhMKldn0ct4dMUPs5HgU-M8M99Hm6X8X2_Q9q-DUSpNgkedu_kXYcdm_W3XDNBPP0UhqhaE0f6S4kdEEI2ekAAfNOlsxdIjw3JkZTJZSERD_26yUQAy1G37d9Gv8pweBaonQTPVxo4CRox-sFlio4P1gJ-DEpkO-2tV1v4zhrURKF9NfBASpf8gn11v-R9BHxA9l7w3l42LwtQoFX0r-3DK6RTu5GAxgNSP5kAZqHTXOL65YRW8DwLYR7c2BLwPalwr97zrusF0xZcxC5Sw7ngGBWQAReShUn0XuZjpXXi-qRSo_l7lzTi2TxbmAUDKri_5rc7eTNCdoCmDqj60gM1_D3NfvkmdTU3xvoreTXZNweClFa8-caVGAmtRiyCNG-tR6IXOAGZah-ahU5pXGkXYK593oDbJ01xyRP3xd5XPxzhsbAanpMUoue5m_4IgNlaJCLJCJ0AnuVwJluHeh8eYChlHf58rrX1dfkzdSe-nmRs6y7EoWUavKqv3k2grqSoTQpIjP7Sy0HmQF6FO-MLm2tgCQCpAPCe87SzXDqzvGPFoEBL2J36mbYr5ToFmewoJhlJdwRDTJAGbr5zLi_pH5H6klrPwuUw7a2oSUM576RjI81cca4u0-yP71I3dY2OLP36xCXc8LTw8aI22KdjxAB_NnAXUYxlxivA7PDPeAVW558FUoRxhr1a6OPGVUy5AiB5J6fnA5QWcFgvJ04qwxYLj9njZDatravxtRyseA09MCqk8q7I_fqG9T7KW0832AXXhAWCtI9TiLyYn7rFAR3MS62GtWSC5RJnr__LBUFgozUvT1r3l51C2dC5uQPkRCTLDz6u9iB5dNkz-sZv4C5pwaRowSvSFvROKzbNFLkHtXpTFkMR6riK-OGitFJ6xbwgu22rpoImALwXQ2Ynvch0Nzz5-m1oOqm5Nzwurwq2phIF0pUE2s4NAP0QYdg97poJAPm7WdffnLiI8vM7Iiis-yIEbWUr2eniV5-C6KDGxeaqzjnPcKFnss9hLbwawMz9DCFB7EeWZhFwGBgaXF2Q6W4WMW3JMs7OEn6eNaBXo4J9oOTiOzfCot_xoIsp6PKUcCwjN24c8OVvpOeoY1OeEiJ8KaXdhNEkWnpqor-GBqcdo6dUc5MtQozoeqP59UkzTkwSpm9hb2rQrYFUAO1J2LimoPMgf1k2Cz_mCFMljRzAtWbjORmIq1cYkzRjr_M9F8roJUrCWMREmJbaOqEhaBLy7CGV57CpdRUX_zqk1ZO3wQNvlsEqggi5mKZtiD2EF-u3FatMOLP2ZkGMSb5xh184Fm5BP9GI5Uyvs9vmjNbD51HOBClycZolW9OhL5ZpqJNEHACPkh2b8rTUHGkPE0Pa3Zq4OTFwTji09PStzgda-kyR38KRZ6DhNyfdPtEaiK_t88YCsbrNUkUwX5Ge8GUaBh4tempT3wgofqR0ugCnqVS_YN2LxyNStn2GUeKXFbe4yS_ZkM41pyH7NbUrYZWRA94p6X2nNYwXrATngUZXeKvH9N7Bc3Rawnj6j5jA0JAZdMJ6op7zd5-L9rl3NkUkrmi7pmH55iRjtthL-kvO7HiwHriPzD3tks-2KLf6Vm769Kmx-K6QGO9bhGhKGL00sBmUB7tN9kUSt59srT_sS8uZ4YLvA7OzjRATRinwRqbk6pafdRM40W5OnPdhcll55KuwuTtyT_4C1CUbRjmm_U0nyxu-MV1lCnSMStJc62MXqeVwweIw2DJCxxT63_9F54GSGnnRAIqK2eEQBjmeBlNXljVkGWDGpugTu3c1x8LaHbfj1O6Uq1sBrgFY2LUWx4DfDgTPqZxUTB9nBx9XkCPMu6xelYfmK6wiU7PRUVpu7ufH3xarlhwKEfs5fM2qV7e0xx9IDhDVK5pxOLI5oyu6giG4wmHYWiOqRuxYqBYEUTfitK2ikqq74HmSKtmfxnI4XsZiNtptye73sYcTnzYBajVlP8sF6cecTBheW31PhehJsWbJwQFKP-QWkflUCo7t7373ZlR4CStNYwT84RHFn9rjrvLBogS4_UL32ZMLHo5HMmx268fo5vOxcZNpLmphZxlcxwsaH_A-IPagi2UmqvfcFR7hb9ABgj4x8hRJ43pUhMNgiLIbRtoqHSj8ZFhK-Ck_GkeqRV0S4F1s8P9I7B7WHzHZWJK5XGra9-u1RWJICjWc2OiWSR3t70dce_UkrmpCHiot4z4e5r3mBGMVOEoSo1MPlMNJcEuMnXyNs0TjI-0xkCibhocXbV6cdm1rV-lCyegDiIEpQM1IMj5ihc-R8PogIjc1Na8zTr51VCcEhmjqOymQuSgvJjpdtvMUBERw8c9b1yy2Dbj02GL4HhE3a_JCv-EH9LtfZB0Eoz3d5VoDWgtAULwk526U7E3hN2X7pZfwBv9h9XBP9Xddgwdo4YaQKCigyqBh1omJL-TIbTmD468JbSUJyqHy-RY7uFSityAtvpv_CNRpYl63FVTGZDs7SQHw3EhzoDofYqLbcWYvCwodudqDMXx8kU6sWHibMt18sjpN2pKNiWmP-UYzEnS46_iZKy7KsepjaiSg2OQJE744230HicR7-MbSGLDUbrL_gj8F8XEdzdyoLgtE7xvM-Uae7RkSnQ_Ii6iV3pN8jzQxQ9EYEjQb1ubMBSaFGO8LJasKC7jc3IlNydfyMptfjNhfibxBHCVquEVvYCcsDViOWB3ZJUQXwdmsfVG1o7XcClF4tR2daoD9uXeKTbpv9cGHperMu3Gxw0iE5wM-w6Fla7gYAVqmJzkdHymB2wELp32qYJZiwgjDSFIh5-jvOH6AAxivMDu8PEOHS03n8n3P09QaXTcIC9YeH-Yszuy5wAAAAAAAAAAAAAAAAAAAAkRGB4lKA"
./build/cmd/smo-node/smo-node --daemon --port 7778 \
  --data /tmp/smo-test/nodeB \
  --name "NodeB" \
  --join "$JOIN_TOKEN" > /tmp/nodeB.log 2>&1

# Terminal 3: Tail logs
tail -f /tmp/nodeA.log /tmp/nodeB.log
```

---

## 6. Debug Instrumentation (add to code)

### 5.1 Version handshake (framing.cpp)
```cpp
// In version_handshake_client
printf("[DEBUG] client send version=%u\n", client_ver);
printf("[DEBUG] client recv version=%u\n", server_ver);

// In version_handshake_server
printf("[DEBUG] server recv version=%u\n", client_ver);
printf("[DEBUG] server send negotiated=%u\n", negotiated);
```

### 5.2 PQ handshake (secure_session.cpp)
```cpp
// In client_handshake
printf("[DEBUG] client send ClientHello\n");
printf("[DEBUG] client recv ServerHello\n");
printf("[DEBUG] client send ClientFinish\n");

// In server_handshake
printf("[DEBUG] server recv ClientHello\n");
printf("[DEBUG] server send ServerHello\n");
printf("[DEBUG] server recv ClientFinish\n");
```

---

## 6. Exit Criteria for This Discussion

| Check | Done? |
|-------|-------|
| A starts clean on 7777 | ✅ |
| B joins A on 127.0.0.1:7777 | ❌ |
| Both logs show version handshake success | ❌ |
| Both logs show PQ handshake steps | ❌ |
| A and B complete SecureSession handshake | ❌ |
| SecureSession established (no shutdown) | ❌ |
| Packet path test: A→B seal→open→response | ⏳ |

**Only after A↔B PASS**, then:
1. Add Node C (7779) with same join token
2. Verify 3-node mesh gossip sync
3. Run G3 packet tests across A↔B↔C

---

## 7. Scope Boundary

**This discussion covers ONLY PQ handshake debug on localhost.**  
G3 Packet Auth (P0–P8) is **frozen** — 25/25 ctest + 24/24 PCT pass. No changes to:
- `packet_crypto` (AEAD)
- `ReplayWindow`
- `packet_dispatcher`
- `packet_route`

**Next discussion after this:** DISCUSSION_0045 3-Node Deployment Verification (with this A↔B working as prerequisite).

---

## 8. ROOT CAUSE (2026-09-18) — Connection-protocol demux missing

The failure was **NOT** in the PQ handshake or G3. It is a **protocol mismatch on TCP :7777**.

### Evidence
- Client join (`core/enroll/auto_enroll.cpp:417-475`): version handshake → `write_field(fd, req_cbor)`
  → sends a **plain CBOR `JoinRequest`** (no length prefix beyond u16) with **NO PQ handshake**.
  This was intentional as of commit `593c27c` (v0.0.7): "write_field/read_field public for join-domain".
- Server (`cmd/smo-node/main.cpp:2338`): if `server_cert_blob` non-empty → `SecureSession::server_handshake()`
  (mutual-auth PQ) then `dispatch_packet_session()`.
- A freshly joining node has **no certificate** (only keypair + CSR), so it cannot do mutual-auth PQ.
- Server reads the ~18,654-byte CBOR `JoinRequest` as the **PQ client KEM public key**, then blocks
  waiting for a client cert that never arrives → client read times out → closes →
  server logs `connection closed during secure read`.
- Even if PQ succeeded, `dispatch_packet_session()` only accepts a valid G3 `Packet` and **cannot**
  route `JoinRequest` to the raw handler; only `dispatch_session()` falls through to `raw_handler_`
  (`core/network/packet_dispatcher.cpp:264`).
- No discriminator exists: `version_handshake_client/server` only exchanged a single `uint32` version.

### Architecture intent
```
TCP :7777
  ├── JOIN / ENROLL : version + type=JOIN → plain CBOR JoinRequest
  │                    → dispatch_session() → raw_handler
  └── DATA          : version + type=DATA → PQ SecureSession
                       → G3 packet → dispatch_packet_session()
```

### Fix (chosen: Option 1 — connection type in version handshake)
1. Add `ConnectionType { Data=0, Join=1 }` to `core/transport/framing.hpp`.
2. Version handshake exchanges `[version:4][type:1]` both directions.
3. `auto_enroll.cpp` join path sends `ConnectionType::Join`.
4. `smo-node` accept loop: `JOIN` → skip PQ → `dispatch_session()` (raw JoinRequest);
   `DATA` → PQ handshake → `dispatch_packet_session()`.
5. No changes to frozen G3 components (`packet_crypto`, `ReplayWindow`, `PacketDispatcher` G3 path).

### Note on Option 2 (rejected)
One-way PQ for enrollment was rejected: the join node has no cert, forcing it into PQ mutual-auth
is the wrong abstraction, and `dispatch_packet_session()` cannot carry a raw `JoinRequest`.

## 9. Following the demux: enrollment/bootstrap bugs + `ConnectionType::Sync` (2026-09-18)

After the demux fix, A↔B reached progressively deeper and exposed three independent bugs plus one
architectural gap. **G3 (P0–P8) is frozen and MUST NOT be touched** — this section is about the
bootstrap/enrollment flow of DISCUSSION_0045, not G3.

### 9.1 Bug: `mesh.json` `root_public_key` truncated → `Join Token signature mismatch`
- Symptom: server rejected the token with `Join Token signature mismatch` even for a freshly issued token.
- Root cause: `~/.smo/meshes/testmesh/mesh.json` stored a **corrupted/truncated** `root_public_key`
  (2111 hex chars, odd) while `recovery.pkg` held the correct 3904 hex chars (1952-byte ML-DSA-65 key).
  `MeshAuthority::open()` reads `mesh.json` because there is no `root.cert` (`core/authority/authority.cpp:185-228`).
- The issuer fingerprint check only compares the **leading 16 hex** (8 bytes), so the truncated key
  passed the fingerprint gate but failed actual signature verification.
- Fix applied (data repair, not code): set `mesh.json` `root_public_key` = `recovery.pkg`
  `root_public_key` (3904 hex). Backup kept at `mesh.json.bak`.
- TODO (hardening): `MeshAuthority::open()` should reject a `root_public_key` whose length does not
  match the suite's public-key size, instead of silently using a truncated key.

### 9.2 Bug: bootstrap-sync client omitted cert + signing key → `ML-DSA: invalid secret key size`
- After a successful join, Node B requests bootstrap sync (`core/enroll/auto_enroll.cpp:612-735`).
- The bootstrap-sync client built `SecureSession::Config` **without** `client_cert` /
  `client_signing_secret_key`, so `client_handshake()` signed the ClientHello with an empty key and
  the ML-DSA provider threw `std::runtime_error("ML-DSA: invalid secret key size")`, aborting Node B.
- Fix applied: load `actual_data_dir + "/cert.smoc"` and `identity->secret_key()` into the config
  (mirrors `cmd/smo-node/main.cpp` and `cmd/smo-cli/cli_context.cpp`).
- TODO (hardening): `SecureSession` must return an error instead of throwing for invalid key sizes,
  and `Config` validation should reject empty mutual-auth material for `Role::Client`.

### 9.3 Bug: certificate `mesh_id` hex-decoded a human name → `Certificate mesh_id mismatch`
- `MeshAuthority::issue_certificate()` stored `cert.mesh_id = hex_to_bytes(mesh_id)`, but `mesh_id`
  is a **human name** (`"testmesh"`), not hex. `hex_to_bytes` produced garbage bytes, while
  `SecureSession::verify_peer_certificate()` compares the raw bytes as a plain string to
  `config_.mesh_id` (`core/transport/secure_session.cpp:647-654`) → mismatch.
- Fix applied: store the raw name bytes (`cert.mesh_id.assign(mesh_id.begin(), mesh_id.end())`) at all
  three sites in `core/authority/authority.cpp` (issued cert + root cert + authority cert).
- Certificates issued before this fix carry the garbage mesh_id and must be re-issued.

### 9.4 Architectural gap: bootstrap sync vs. G3 DATA on the same connection type
- After mutual-auth PQ succeeded, the server routed the DATA connection to
  `dispatch_packet_session()`, which requires a valid G3 `Packet`. But the bootstrap-sync client sends
  **raw application CBOR** (`sec.send(req_cbor)`) inside the `SecureSession`, producing
  `Failed to parse packet: unsupported packet version`.
- `BootstrapSyncRequest` is an **application-level** CBOR message carried inside `SecureSession`,
  not a G3 DATA packet. Therefore `ConnectionType::Data` is the wrong path for it.

### Fix (approved): add `ConnectionType::Sync`
Decision: keep G3 frozen; introduce a dedicated connection type for raw-CBOR-over-SecureSession.

```
accept TCP
  ├── Join ──→ plain CBOR → dispatch_session()/raw_handler
  ├── Sync ──→ PQ handshake → SecureSession → raw CBOR BootstrapSync
  │              └── dispatch_session()/raw_handler
  └── Data ──→ PQ handshake → G3 packet → dispatch_packet_session()
```

Implementation:
1. `core/transport/framing.hpp`: `ConnectionType { Data=0, Join=1, Sync=2 }`.
2. `core/transport/framing.cpp`: map the echoed byte to `Sync` explicitly.
3. `core/enroll/auto_enroll.cpp`: bootstrap-sync client uses `version_handshake_client(fd, ConnectionType::Sync)`.
4. `cmd/smo-node/main.cpp`: a `SecureTransportSession` adapter exposes a post-handshake
   `SecureSession` as a `TransportSession` (raw `send`/`recv`), so `Sync` connections can reuse
   `dispatch_session()`/`raw_handler` without copying protocol logic or touching G3.
5. `Data` continues to use `dispatch_packet_session()` unchanged.

### Order of operations (per review)
1. Do not modify `packet_crypto`, `ReplayWindow`, or the G3 path.
2. Add `ConnectionType`.
3. Route `Join`, `Sync`, `Data` by type.
4. Re-run 25/25 ctest, 24/24 PCT, then NodeA+NodeB local, then NodeC to exercise bootstrap sync.
5. No VPN yet — three nodes on `127.0.0.1:7777/7778/7779` is the correct first deployment check.

### Clarification
P8 ended **G3**, not the whole SMO effort. The remaining work is completing the
DISCUSSION_0045 bootstrap/enrollment flow.

### 9.5 Bug: manifest signature domain mismatch → `manifest delta signature verification failed`
- After `ConnectionType::Sync` was wired, the bootstrap-sync request reached the server and the
  response decoded: `OK (mf=1 mem=1 crl=1 pol=1 seeds=1)`. But the client then failed with
  `Error: manifest delta signature verification failed`.
- **Root cause:** signer/verifier used different byte domains.
  - Server (`core/join/join_protocol.cpp`, `process_bootstrap_sync`) signed the CBOR envelope
    payload `{1: manifest_data, 2: bstr(""), 3: epoch}` (placeholder signature).
  - Client (`core/enroll/auto_enroll.cpp`, ~l.766) verified `manifest_data || epoch_be64`.
- **Fix:** align to the documented contract (DISCUSSION_0046 Q6: `canonical(data || epoch || prev_hash)`;
  `prev_hash` still pending). Server now signs `manifest_data || epoch_be64`; the envelope still
  carries `{1:data, 2:sig, 3:epoch}`. Client unchanged.
- Result: `manifest: signature VALID (epoch=1)`, `membership delta: 4198 nodes`, then
  `Successfully enrolled!` with `Bootstrap: 1 seed(s)`.

### 9.6 Operational: stale `smo-node` broke successive test runs
- Symptom: server log `Failed to listen TCP: TCP bind failed`, large runs of NUL bytes in
  `/tmp/nodeA_debug.log`, and Node A `shutting down` ~5 s after start (as Node B launched).
- Cause: a `smo-node` from a previous run still held `:7777`; the new A failed to bind while the
  stale A (old binary) served the join and then exited. Two writers to the same log produced the
  NUL holes.
- Fix (test harness only): `test_local_ab.sh` now runs `pkill -x smo-node` + `sleep 1` before
  starting, so every run is clean. Use `pkill -x` (process name) to avoid matching the invoking
  shell's own command line.

### 9.7 Bug: daemon ignores SIGTERM → stale process holds the port (correcting 9.6)
- `pkill -x smo-node` (SIGTERM) does **not** terminate the node: the signal handler only sets
  `g_running=false`, but the main loop keeps blocking, so the process survives and keeps its
  listening socket. The next run's server then fails to bind:
  `Failed to listen TCP: TCP bind failed`.
- This was the real cause behind 9.6 (not just "a stale process"); the new A then `return 1`s,
  while the *old* A finally notices the flag and `shutting down` a few seconds later — exactly
  when the joining node needs it, so the join/sync `read failed during version handshake`.
- Harness workaround: `test_local_ab.sh` / `test_local_abc.sh` use `pkill -9 -x smo-node`
  (`-x` = exact process name; never matches the invoking shell).
- **Product TODO:** make shutdown prompt — wake/stop the accept loop (self-pipe / non-blocking
  accept with timeout) so SIGTERM is honored. Also affects `smo-node` restart ergonomics.

### 9.8 Bug: certificate filename mismatch → `no certificate ..., PQ handshake disabled`
- Enrollment (`core/enroll/auto_enroll.cpp`) wrote the issued cert to `<data>/cert.smoc`.
- The daemon and CLI read `<data>/node.cert.smoc` (`cmd/smo-node/main.cpp` x3,
  `cmd/smo-cli/cli_context.cpp`). Starting an enrolled node therefore logged
  `Warning: no certificate at .../node.cert.smoc, PQ handshake disabled` and refused mutual auth.
- Fix: `auto_enroll.cpp` now saves/reads `<data>/node.cert.smoc` (canonical, matches daemon).
  Success message also prints the corrected path.

### 9.9 Known minor issues (not blocking)
- Registry gains a stray node row with empty `display_name` on each enroll
  (`nodes`: `nodea, nodeb, nodec, ''`). Likely `enroll_node` inserting the CSR's empty name;
  should be deduped/constrained.
- `process_bootstrap_sync` prints `membership delta: %zu nodes` but passes a **byte** count
  (`4198`), which reads as 4198 nodes. Cosmetic.

### 9.10 Status: Phase 2 (Node C) passes
- `test_local_abc.sh`: A (`:7777`, authority) + B (`:7778`, enrolled member) + C (`:7779`, fresh
  join). C completes PQ handshake, certificate verify, bootstrap sync
  (`manifest: signature VALID (epoch=1)`), and `Successfully enrolled!`; A registers
  `nodec` active. A/B/C all reach `Node state: ACTIVE` / `entering main loop`.
- Registry after run: `nodea`, `nodeb`, `nodec`, `''` all active.
- `25/25 ctest` and `24/24 PCT` pass after all fixes (9.5, 9.8).
- Remaining: remove `[DEBUG]` instrumentation; fix 9.7 (shutdown) and 9.9.

### 9.11 Cleanup: `[DEBUG]` instrumentation removed (2026-09-18)
- Removed all debug `fprintf(stderr, "[DEBUG] ...")` from `core/transport/framing.cpp`,
  `core/transport/secure_session.cpp` (`client_handshake`/`server_handshake`),
  `cmd/smo-node/main.cpp`, `cmd/smo-cli/cli_context.cpp`, and
  `core/enroll/join_token.cpp` (`calculate_payload_len` traces).
- `reference/OLD_SHELLMAP/**` left untouched (not built).
- Rebuild clean; `25/25 ctest` and `24/24 PCT` pass.
- Re-ran `test_local_abc.sh` (B already enrolled + fresh C): A/B `ACTIVE`, C
  `Successfully enrolled!` with `manifest: signature VALID (epoch=1)`, registry
  `nodea/nodeb/nodec` active, zero `[DEBUG]` lines in logs, no bind/shutdown errors.
- Baseline is clean; next hygiene items are 9.7 (prompt shutdown) and 9.9
  (`display_name=''` row, membership printf).

### 9.12 Gossip/heartbeat diagnosis — 3-node runtime (2026-09-18)
- `smo-cli`/`smo-admin` `✓`/`✗` glyphs replaced with `[~]` (pass) / `[!]` (error).
- Added typed TCP connect: `Transport::connect(ep, ConnectionType)` +
  `TcpTransport` override (defaults to `Data`); the daemon `--seed` bootstrap now
  connects with `ConnectionType::Sync` so the seed routes it to the raw handler
  (`cmd/smo-node/main.cpp:~1161`).
- Verified with `smo-node --daemon --seed 127.0.0.1:7777`:
  - A (seed) logs `Raw handler: HelloMsg` for B and C; B/C log
    `Seed responded: NodeA (tcp://127.0.0.1:7777)` + `Bootstrap complete. Peers: 1`.
  - B/C peer.db each contain `NodeA` (state=Online). A's peer.db stays empty.
- Root cause of "no peer/gossip/heartbeat progress": the runtime loop is
  architecturally incomplete:
  1. **Main loop blocks on TCP `accept()`** (`cmd/smo-node/main.cpp:2321`) — all
     periodic work (`sync_service.tick`, discovery/heartbeat `tick`, 5 s telemetry,
     30 s `peer_store.sync_from_membership`, UDP datagram dispatch) only runs while
     a new TCP connection is being accepted. Idle nodes do nothing.
  2. **`gossip_engine.start()` never called** (only `stop()` at cleanup).
  3. **No `sync_service.on_delta("membership", …)`** — membership changes are
     never queued/broadcast via gossip (only crl/policy/manifest registered).
  4. **HelloMsg carries no endpoint** (`node_id`+fingerprint+version only) — the
     seed records the joiner at its ephemeral outbound TCP port, so it cannot be
     reached for heartbeat; real endpoints (7778/7779) never propagate.
  5. **Heartbeat PING/PONG UDP path is broken**: pongs reply to the pinger's
     ephemeral connect socket (no reader), and `handle_pong` matches membership by
     endpoint, which never equals the ephemeral source UDP port — so pongs never
     count, and liveness timeout would never resolve.
- Concrete next step: repair 5.1 + 5.3 + 5.2 (poll-based main loop, membership
  delta wiring, gossip start) and 5.4 (advertise endpoint in HelloMsg), then fix
  the heartbeat UDP round-trip (5.5). Kill/restart liveness test afterwards:
  A/B/C ACTIVE → kill one → peers mark offline → restart → reappears.

### 9.13 Phase 1-2: main loop + gossip enable (2026-09-18)
- **Phase 1 — main loop no longer starves.** Replaced the blocking
  `lstnr->accept()` with `poll(...,250ms)` + accept-on-POLLIN
  (`cmd/smo-node/main.cpp:2321`); added `TransportListener::fd()` (virtual, -1
  for non-fd) + `TcpListener::fd()` override. Now the per-iteration work always
  runs while idle: `sync_service.tick`, 5 s discovery/heartbeat tick, 30 s
  `peer_store.sync_from_membership`, UDP datagram dispatch, telemetry export.
  Verified: all 3 daemons log `node DEGRADED — heartbeat=yes ... uptime=31s`
  (readiness check now fires), `metrics.prom` mtime fresh, A's peer.db gains B/C
  and heartbeat marks them `Offline (state=3)` after 3 missed pings.
- **Phase 2 — gossip engine started**: `gossip_engine.start()` after
  `sync_service.start()`; B/C report `gossip_tx=yes` at the 30 s readiness check.

### 9.14 Phase 3 — gossip transport works (2026-09-18)
- Gossip sender (`core/discovery/gossip.cpp::send_gossip_to_peer`) now does a
  version handshake as `ConnectionType::Join` and delivers its GOSP frame via
  `write_field` (2-byte length prefix). The receiver already routed GOSP through
  `PacketDispatcher::dispatch_session` (`packet_dispatcher.cpp:223-235`), so the
  frame now reaches `GossipEngine::apply_gossip`.
- `DiscoveryEngine::set_membership_sync()` + emit `PeerAdded` events from
  `handle_hello`/`handle_welcome` so discovered peers enter the gossip event log
  (`core/discovery/discovery.cpp`).
- Verified (25/25 ctest, 24/24 PCT): A logs `node READY — 3 peer(s),
  gossip tx=3 rx=2`; B and C deliver gossip to A (`gossip_tx=yes`), A receives
  and applies 2 frames (Membership events re-emitted). A→B/C fan-out still dead
  this phase because A only holds B/C at their ephemeral source ports — endpoint
  advertisement is Phase 4.