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