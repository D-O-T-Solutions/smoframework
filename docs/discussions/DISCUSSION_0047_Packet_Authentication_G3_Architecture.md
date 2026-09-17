# DISCUSSION 0047 — G3 Packet Authentication: Architecture Conflicts & Open Decisions

**Status:** DECIDED (2026-08-14) — Decision Log Q1–Q12 đã chốt; sẵn sàng lập implementation plan (chưa code)
**Target:** G3 (packet authentication) trong lộ trình DISCUSSION_0046 §26.4
**Date:** 2026-08-14
**Liên quan:** RFC 0019 (AMEND-4), RFC 0024, RFC 0014, DISCUSSION_0046 (§2-G3, §20.3–20.10, §24.3, §26.4)

---

## 0. Mục đích tài liệu

Tài liệu này **không code**. Nó là phase inventory + conflict analysis cho G3.

> Nguyên tắc đã thống nhất: **không tự suy đoán**. Mọi conflict giữa RFC 0019 AMEND-4,
> RFC 0024 và implementation hiện tại phải được chốt trước khi đụng vào `packet.cpp`.

Mục tiêu G3 (theo 0046 §26.4): packet authentication (seq/nonce/replay window) →
packet negative tests (replay, stale epoch, tamper) → PCT + E2E.

---

## 1. Trạng thái hiện tại (Phase 1 inventory)

### 1.1 Wire format hiện tại (khác RFC 0019 hoàn toàn)

`protocol/packet/packet.h:19-37`

```cpp
struct PacketHeader {
    uint8_t  version{1};          // = 1 (RFC 0019 nói 0x03)
    uint8_t  flags{0};            // không có trong RFC 0019
    uint16_t payload_len{0};      // RFC 0019 đặt payload_length ở offset 37
    uint16_t signature_scheme{0}; // RFC 0019 dùng suite_id (1B)
} __attribute__((packed));        // sizeof == 6 (RFC 0019 header 37/39B)

struct Packet {
    PacketHeader header;
    std::array<uint8_t,16> session_id;  // RFC 0019: có
    std::array<uint8_t,16> intent_id;   // RFC 0019: KHÔNG có
    uint32_t opcode_id;                 // RFC 0019: namespace(1)+message_id(2)
    int64_t  timestamp;                 // RFC 0019: Unix ns (hiện là ms)
    std::array<uint8_t,8> nonce;        // RFC 0019: có
    std::vector<uint8_t> payload;
    std::array<uint8_t,64> signature;   // RFC 0019: variable-length auth
};
```

- `packet.cpp:40` `kExpectedVersion = 1`; `packet.cpp:41` `kFixedSize = 6+16+16+4+8+8+4+64 = 126`.
- `packet.cpp:76,85` hardcode `+ 64` signature và copy 64B.
- Không set/reject nonce = 0; không verify auth; không timestamp window.

### 1.2 Nơi Packet được dùng (blast radius)

| File | Dùng gì | Ghi chú |
|---|---|---|
| `protocol/packet/packet.{h,cpp}` | định nghĩa + serialize/parse | file lõi phải sửa |
| `cmd/smo-cli/cli_context.cpp:811-820,853` | build packet → `packet_to_buffer` → frame → `SecureSession::send`; parse response | **session_id/intent_id/nonce để zero** |
| `cmd/smo-node/main.cpp:1623-1744` | `runtime_handler` dùng `pkt.opcode_id`/`session_id`/`intent_id`; build response | correlation = copy `intent_id` |
| `core/network/packet_dispatcher.cpp:54-91,126-145` | handler keyed by `opcode_id` (u32); lifecycle check `check_opcode_allowed(opcode_id)` | |
| `core/runtime/runtime_bridge.cpp:95-128` | route keyed by `opcode_id`; `bridge()` parse payload JSON | **không dùng `intent_id`** |
| `transport/tcp/tcp_transport.cpp:274,397-422` | `smo::hl::TcpTransport` parse/serialize packet | **chỉ dùng trong test** (xem 1.4) |
| `tests/unit/protocol/test_protocol.cpp:73-173` | packet roundtrip + negative tests | theo format cũ |
| `tests/unit/protocol/test_pct.cpp:573` | PCT-013 ReplayProtector | |

### 1.3 Encryption stack hiện tại — điểm mấu chốt

`core/transport/secure_session.hpp`

- `:15-17` nonce 24B (`kSecureNonceLen`), prefix 16B + counter 8B.
- `:24-31` sau handshake: **toàn bộ data encrypt bằng XChaCha20-Poly1305**;
  wire format mỗi message `[4-byte len][24-byte nonce][AEAD output]`.
- `:107-108` `tx_counter_`/`rx_counter_` (mỗi hướng một counter); `:113` `build_nonce`.

Đường đi thực tế (production):

```text
CLI  : Packet → packet_to_buffer → frame_write → SecureSession.send  (XChaCha20 AEAD)
NODE : SecureSession (server) → recv (decrypt) → frame_read → packet_from_buffer → handler
       (main.cpp:2284-2318; có cert → SecureSession, không cert → plaintext)
```

→ **DATA packet hiện ĐÃ được XChaCha20-Poly1305 bảo vệ bởi SecureSession.** Đây là
xung đột trung tâm với RFC 0019 AMEND-4 (xem C1).

### 1.4 Hai TCP transport khác nhau (de-scope)

- `core/transport/tcp_transport.{hpp,cpp}` — `smo::TcpTransport`, dùng bởi node qua
  `TransportRegistry` (main.cpp:889). **Không** trực tiếp gọi `packet_to_buffer`.
- `transport/tcp/tcp_transport.{h,cpp}` — `smo::hl::TcpTransport` (namespace `smo::hl`),
  có gọi `packet_{from,to}_buffer`, **chỉ dùng trong test**
  (`tests/unit/transport/test_transport_minimal.cpp`, `test_transport_highlevel.cpp`).

→ Có thể coi `hl::TcpTransport` là test-path khi tính blast radius G3.

### 1.5 Session state & replay

- `core/session/session.h:14-22` — `Session` **không có** epoch/sequence/K_session.
- `core/session/session.hpp:93-143` — `Session` FSM (RFC 0014), cũng không có epoch/seq/key.
- `core/session/session.hpp:191-201` — `SessionManager::recover()`: session ACTIVE khi crash
  bị **force Closed** khi restart.
- `protocol/replay/replay.{h,cpp}` — `ReplayProtector` (nonce + timestamp window,
  config 5s/10000). **Chỉ được dùng trong test** (`grep -rn ReplayProtector core/` = rỗng;
  không file production nào include `protocol/replay/replay.h`).

### 1.6 Version numbers đang mâu thuẫn

| Nơi | Giá trị |
|---|---|
| `core/transport/framing.hpp:35` `kTransportVersion` | 1 |
| `protocol/packet/packet.cpp:40` `kExpectedVersion` | 1 |
| RFC 0019 `protocol_version` | 0x03 |

---

## 2. Những gì ĐÃ CHỐT trong phiên thảo luận này (ghi lại để khỏi mất)

> Lưu ý: các mục dưới đây là thống nhất nền tảng (đánh dấu #A/#B). Bộ câu hỏi chính
> Q1–Q12 nằm ở §4 và câu trả lời chốt nằm ở Decision Log §2.5.

- **(thống nhất #A):** Giữ **frozen header RFC 0019**, KHÔNG amend RFC 0019.
  `epoch` + `sequence` là **per-session state**, không serialize lên wire.
  Wire giữ `session_id[16] + timestamp + nonce[8]`; replay window kết hợp per-sender tracking.
- **(thống nhất #B):** AEAD nonce 24B cho DATA plane =
  `BLAKE3(session_id || wire_nonce)` lấy 24B. Giữ nguyên wire nonce 8B.
- **Bắt buộc:**
  - DATA plane = **AEAD-only** theo AMEND-4, KHÔNG ký từng packet.
  - KHÔNG nhét fixed 64B signature vào mọi packet.
  - CONTROL/IDENTITY = digital signature **variable-length theo suite** (64B Ed25519 / ~3309B ML-DSA-65).
- **Chưa code cho tới khi chốt hết conflict dưới đây.**

---

## 2.5. Decision Log (FINAL — chốt 2026-08-14)

### Bảng quyết định

| Câu | Chốt | Ghi chú |
|---|---|---|
| **Q1** | **(b)** Packet layer là owner của DATA AEAD | Chính xác: **Packet DATA authentication owned by Packet layer; `SecureSession` KHÔNG được AEAD Packet thêm lần nữa**. KHÔNG có nghĩa `SecureSession` mất hết AEAD — vẫn AEAD cho non-Packet CBOR (xem **B1 §7.1.1**) |
| **Q2** | **(b)** Wire header trước payload là **39B** | Chuẩn hóa terminology: `37B fixed fields (tới hết nonce) + 2B payload_length = 39B header`; `static_assert` trên **39B** |
| **Q3** | **(b)** `nonce[8]` = monotonic **sequence counter** | Bắt đầu từ `1`; replay window dựa trên sequence |
| **Q4** | **derive** | `suite_id` từ negotiated session suite; auth length suy ra từ `namespace + suite_id`; KHÔNG thêm auth_length vào wire |
| **Q5** | **(a)** Giữ `Opcode` nội bộ + static mapping `Opcode → {namespace, message_id}` | Chưa rewrite dispatcher/bridge; dùng adapter |
| **Q6** | **(a)** Bỏ `intent_id` khỏi wire | Correlation (nếu cần) nằm trong payload; không thêm extension phá RFC 0019 |
| **Q7** | **(a)** Unix **nanoseconds + window 300s** | Theo RFC 0019 |
| **Q8** | **`SessionSecurityState` trong session layer** | State: `epoch`, `tx_sequence`, `rx_epoch`, `rx_highest`, replay window, session key/reference. Enforce tại packet/session authentication boundary; KHÔNG dùng `ReplayProtector` global/test-only |
| **Q9** | **SessionManager/SecureSession phải expose `session_id`** | Packet bắt buộc mang session ID thật; **zero session ID bị reject** |
| **Q10** | **(a)** G3 chỉ DATA-plane Packet authentication | CONTROL/IDENTITY hiện là wire format riêng → không kéo vào G3 |
| **Q11** | **Invariant lifecycle** (xem dưới) | Rekey ⇒ `epoch++`, sequence reset; restart ⇒ session invalid/Closed; không reuse `(session_id, epoch, sequence)` cho plaintext khác; mỗi hướng có sequence riêng |
| **Q12** | **Packet `protocol_version = 0x03`** | `kTransportVersion` giữ độc lập (là version của transport framing, không đánh đồng với Packet protocol) |

### Kiến trúc chốt theo Q1 (b) — KHÔNG double-AEAD

```text
                 ┌─────────────────────────────┐
                 │       SecureSession         │
                 │ handshake / K_session       │
                 │ connection / framing        │
                 └──────────────┬──────────────┘
                                │ K_session
                                ▼
┌────────────────────────────────────────────────────┐
│                    Packet G3                        │
│                                                    │
│ RFC 0019 header 39B                                │
│   version | suite | namespace | message_id         │
│   session_id | timestamp | nonce | payload_length  │
│                                                    │
│ DATA:                                              │
│   plaintext                                        │
│       ↓                                            │
│   XChaCha20-Poly1305                               │
│   nonce24 = BLAKE3(session_id || nonce8)[0:24]     │
│   AAD = canonical 39B header                       │
│       ↓                                            │
│   ciphertext + 16B tag                             │
│                                                    │
│ replay: session_id + epoch + sequence + window     │
└────────────────────────────────────────────────────┘
                                │
                                ▼
                    SecureSession framing → TCP
```

**KHÔNG** dùng: `Packet AEAD → SecureSession AEAD → TCP` (double-AEAD).
**Đúng:** `SecureSession handshake → K_session → Packet AEAD → SecureSession framing → TCP`.

### Wire layout canonical (Q2)

```text
0       protocol_version     1
1       suite_id             1
2       namespace            1
3       message_id           2
5       session_id           16
21      timestamp            8   (Unix ns)
29      nonce                8   (sequence counter)
37      payload_length       2
39      payload              N
39+N    auth                 V   (DATA: 16B tag; suite/plane-derived)
```

- **37B** = prefix tới hết nonce.
- **39B** = fixed header hoàn chỉnh trước payload → `static_assert(sizeof(PacketHeader) == 39)`.

### Nonce = sequence (Q3)

```text
epoch = 7
tx_sequence = 1024

nonce_wire = 1024
nonce_aead = BLAKE3(session_id || nonce_wire)[0:24]
```

Khi rekey:

```text
epoch 7 → epoch 8
sequence 1024 → 1
```

→ tuple `(session_id, epoch, sequence)` vẫn unique.

### Thứ tự xử lý receive (BẮT BUỘC — Q3/Q8)

```text
parse
 → session lookup
 → epoch/window precheck
 → AEAD verify
 → CHỈ KHI authentication thành công mới advance replay state
 → dispatch
```

> **Không được advance replay state chỉ vì nhận được packet.** Packet giả không được
> phép làm receiver "nhảy" `highest_seen`.

### Adapter opcode (Q5)

```text
Opcode::EXEC
    ↓ static mapping
namespace = EXECUTION, message_id = ...
    ↓
existing dispatcher handler (giữ nguyên `opcode_id` nội bộ)
```

→ Đạt RFC wire format mà KHÔNG rewrite toàn bộ runtime architecture.

### `SessionSecurityState` + invariant (Q8/Q11)

```text
Session
 └── SessionSecurityState
      ├── epoch
      ├── tx_sequence
      ├── rx_epoch
      ├── rx_highest_sequence
      ├── replay_window
      └── K_session (key/reference)
```

**Invariant trung tâm:**

> **Một `(session_id, epoch, sequence)` tuyệt đối không được dùng để authenticate hai plaintext khác nhau.**

Các case:

| Case | Rule |
|---|---|
| normal send | `tx_sequence++` |
| receive | replay window per `(session_id, epoch)`; advance chỉ sau AEAD success |
| rekey | `epoch++`, sequence reset |
| restart | session cũ invalid/Closed → không nhận packet cũ |
| new session | session ID mới |
| bidirectional | mỗi endpoint có TX sequence riêng |
| persistence | nếu không persist atomically `key + epoch + sequence` thì **KHÔNG restore session ACTIVE** |

Khớp với `SessionManager::recover()` hiện đã force ACTIVE → Closed (`session.hpp:191-201`).

---

## 3. Conflicts & Ambiguities

### C1 — Double AEAD: SecureSession vs RFC 0019 DATA-plane AEAD ⚠️ NGHIÊM TRỌNG

- RFC 0019 AMEND-4: `AEAD_Encrypt(K_session, nonce, plaintext, AAD=header)` cho DATA packet.
- `SecureSession` **đã** encrypt toàn bộ wire payload bằng XChaCha20-Poly1305 (1.3).

Nếu làm cả hai:

```text
Packet plaintext → Packet AEAD → SecureSession AEAD → TCP   (2 lớp)
```

Cần chốt **chủ sở hữu** của DATA-plane AEAD. Liên quan trực tiếp tới:
- AAD = header (RFC) — nếu SecureSession đã encrypt cả header+payload thì AAD binding khác.
- 2 lớp replay (SecureSession counter + packet replay window).
- Hiệu năng & tính tối thiểu (nguyên tắc "ít thay đổi protocol nhất").

### C2 — "37B header" vs 39B trong chính RFC 0019

Phép cộng theo bảng field RFC 0019 (`:53-62`):

```text
protocol_version(1) + suite_id(1) + namespace(1) + message_id(2)
+ session_id(16) + timestamp(8) + nonce(8)               = 37  (offset 0..36)
+ payload_length(2)                                      = 39  (offset 37..38, payload @39)
```

- RFC 0019 `:16`, `:101` gọi "**Fixed 37-byte header**".
- RFC 0019 `§4` struct `:81-90` **bao gồm** `payload_length` → `sizeof == 39`.
- RFC 0019 `:92` "auth/signature starts at offset `39 + payload_length`".

→ Tài liệu dùng "37" cho bytes-through-nonce, nhưng fixed prefix trước payload là **39B**.
Nếu implementation `static_assert(sizeof(PacketHeader)==37)` sẽ sai. Phải chốt con số frozen
chính thức và cách gọi.

### C3 — Nonce semantics: random-unique vs sequence

- `ReplayProtector` coi nonce là **giá trị ngẫu nhiên duy nhất** (set `seen`).
- AMEND-4/§20.4 nói đến **sequence + window** (`highest_seen=1000, window=64`).
- RFC 0019 `:66` **zero nonce bị REJECT**, nhưng `cli_context.cpp:811-817` để nonce = zero.
- RFC 0019 `:104` "8-byte nonce đủ khi kết hợp per-sender sequence tracking".

Câu hỏi: wire nonce là (a) random 8B chống trùng, hay (b) chính là **sequence counter**
(đặt vào 8B nonce)? Nếu (b), cần cấm zero (bắt đầu từ 1) và thống nhất với
`BLAKE3(session_id||nonce)`.

### C4 — `suite_id` nguồn gốc + độ dài auth variable

- RFC 0019 header có `suite_id` (1B); struct hiện tại không có (chỉ `signature_scheme` u16).
- Auth length **suy ra từ plane + suite** (RFC 0019 `:62,92,105`): DATA=16B tag;
  CONTROL=64B (Ed25519) / ~3309B (ML-DSA-65).
- Parser phải biết expected auth length **trước khi** đọc hết packet → cần biết suite.
  Nhưng `packet_from_buffer` được gọi ở tầng transport, có thể chưa có session context.

Câu hỏi: `suite_id` lấy từ đâu (SecureSession đã negotiate)? Auth length **derive** hay
đọc explicit length field? Nếu derive mà suite_id sai/hỏng thì parse thế nào?

### C5 — `opcode_id` (u32) → `namespace`(1) + `message_id`(2)

- `opcode.h:8-66` — enum `Opcode : uint8_t`, **không có khái niệm namespace**.
- Dispatcher/bridge/lifecycle đều keyed bằng `opcode_id` u32.
- RFC 0019 `:55` namespace: 0x01=DISCOVERY, 0x02=CONTROL, 0x03=EXECUTION, 0x04=DATA.

Câu hỏi: cần **mapping table** `Opcode → {namespace, message_id}`. Ai sở hữu? Giữ
`opcode_id` nội bộ (adapter) hay đổi toàn bộ handler registry sang `(namespace, message_id)`?
Opcode nào thuộc namespace nào (LS/PUT/GET/EXEC vs discovery/bootstrap/join/governance)?

### C6 — `intent_id` biến mất khỏi header

- Packet hiện có `intent_id[16]` (RFC 0041 correlation). RFC 0019 **không có** `intent_id`.
- Thực tế: `runtime_bridge.bridge()` (**không** dùng intent_id); `cli_context` để zero;
  chỉ `main.cpp:1680,1708` copy lại `intent_id` khi build response.

Câu hỏi: bỏ hẳn, chuyển vào payload (JSON req_id), hay giữ như extension ngoài RFC?
(Rủi ro: request/response correlation nếu sau này client dùng.)

### C7 — Timestamp: đơn vị + window

- RFC 0019 `:58,68`: Unix **nanoseconds**, window default **300s**.
- Implement: `int64_t timestamp` **ms** (`cli_context.cpp:814`), `ReplayConfig 5s` (replay.h:17).
- Node dùng ns ở chỗ khác (main.cpp `now_ns`).

Câu hỏi: chốt ns hay ms? Window 300s (RFC) hay 5s (hiện tại)?

### C8 — Fixed 64B signature trong struct + parser

- `packet.h:36` `std::array<uint8_t,64> signature`; `packet.cpp:41,76,85` hardcode 64.
- RFC AMEND-4 yêu cầu **variable-length** auth. `kFixedSize` hiện tại (126) sẽ đổi hoàn toàn.

Câu hỏi: đổi thành `Bytes auth`? Khi đó `packet_from_buffer` cần biết độ dài (C4) +
kiểm tra biên. Negative test cho auth length sai/thiếu.

### C9 — Nơi enforce replay + state ownership

- `ReplayProtector` test-only, global nonce set, không per-session, không epoch.
- AMEND-4: kiểm tra `session → epoch → nonce/sequence → replay window`.
- Chưa có nơi lưu `(session_id, epoch) → replay_window`.

Câu hỏi: enforce ở tầng nào (SecureSession / dispatch_session / transport)? Ai giữ state?
Có cần `SessionSecurityState{epoch, tx_seq, rx_highest, window}` không (đã đề xuất, chưa chốt)?

### C10 — `session_id` binding: CLI gửi zero, SessionManager không match

- `cli_context.cpp:811-817` không set `session_id` → zero.
- `main.cpp:1630-1638` `has_session = pkt.session_id.size() >= 16` (array luôn 16) → luôn lookup
  zero-id → không bao giờ match session thật.
- SessionManager keyed by `SessionId`; SecureSession không expose session_id ra packet.

Câu hỏi: `session_id` trên packet lấy từ đâu? SecureSession cần expose session_id không?
Nếu không bind, replay per-session & policy lookup vô nghĩa.

### C11 — Invariant: (session_id, epoch, sequence) không được authenticate 2 plaintext khác nhau

- `SessionManager::recover()` force Closed khi restart (session.hpp:191-201) → tốt cho replay
  (old session invalid), NHƯNG cần chốt: session key có persist không? epoch/sequence có
  persist không? Nếu key persist + sequence reset về 0 mà epoch không đổi → nonce reuse.

Cần chốt rule cho: **epoch rollover, session recovery, session persistence, rekey,
bidirectional sender, restart**.

### C12 — Bidirectional sequence: nguồn sự thật

- `SecureSession` đã có `tx_counter_`/`rx_counter_` (per-connection, mỗi hướng).
- Nếu packet layer thêm sequence riêng → 2 nguồn. Cần chốt 1 nguồn duy nhất.

### C13 — Version reconciliation

RFC `protocol_version=0x03` vs `kTransportVersion=1` vs `Packet.version=1`.
Cần chốt giá trị nào, có bump không, và `protocol_version` per-packet hay chốt lúc handshake
(RFC 0019 `:70` nói chốt lúc handshake nhưng header vẫn mang per-packet).

### C14 — Plane nào thực sự đi qua `Packet`?

- Hiện `Packet` chỉ dùng cho EXECUTION/runtime (EXEC, CONTRACT_MGMT, WITNESS, ...).
- CONTROL/IDENTITY (join token, cert, manifest, governance, attestation) đi bằng **wire format
  riêng** (length-prefixed field / CBOR), KHÔNG qua `Packet`.

Câu hỏi: G3 có cần implement CONTROL/IDENTITY signature **trong Packet** bây giờ không,
hay chỉ DATA-plane AEAD + replay là đủ cho phạm vi hiện tại?

### C15 — Nguyên tắc tối thiểu vs full rewrite

User đã chọn "full rewrite header sang RFC 0019". Nhưng C1 (double AEAD) và C14 (plane scope)
có thể cho thấy chỉ cần **đổi format header + replay metadata**, giữ SecureSession làm lớp AEAD.
Cần chốt ranh giới chính xác trước khi sửa.

---

## 4. Câu hỏi cần anh trả lời

> Mỗi câu ghi rõ: conflict, options, và đề xuất (lean). Trả lời bằng số, ví dụ "Q1 → (a)".

**Q1. DATA-plane AEAD thuộc về ai?** (C1)
- (a) `SecureSession` LÀ lớp AEAD; `Packet` chỉ mang metadata (nonce/replay/suite),
  header đi kèm như AAD logic. — *ít thay đổi nhất, tránh double encryption.*
- (b) `Packet` làm AEAD; `SecureSession` chỉ còn handshake + key derivation (bỏ AEAD per-message).
- (c) 2 lớp có chủ đích (defense-in-depth) + giải thích lý do chấp nhận chi phí.
- **Lean: (a)** — khớp "ít thay đổi protocol nhất"; nhưng cần định nghĩa lại "AAD=header"
  cho đúng vì header đã nằm trong stream được SecureSession bảo vệ.

**Q2. Con số frozen của header?** (C2)
- (a) 37B = bytes 0..36 (through nonce); payload_length tách riêng ở offset 37.
- (b) 39B = bao gồm payload_length; sửa lại câu chữ "37-byte header" trong RFC 0019.
- **Lean: chốt 1 con số duy nhất, khuyến nghị ghi rõ "37B header (không tính 2B payload_length);
  fixed prefix trước payload = 39B"** và sửa RFC cho nhất quán.

**Q3. Wire nonce là gì?** (C3)
- (a) random 8B, unique set như ReplayProtector hiện tại.
- (b) sequence counter (monotonic, bắt đầu ≥1), replay window theo `highest_seen`.
- **Lean: (b)** nếu muốn khớp AMEND-4 (sequence + window); (a) nếu muốn tối thiểu, giữ
  ReplayProtector cũ.

**Q4. `suite_id` + auth length?** (C4)
- Chốt nguồn `suite_id` (SecureSession negotiated?) và cách parser biết độ dài auth
  (derive từ plane+suite, hay explicit length field).
- **Lean:** derive từ `namespace + suite_id`, cả hai có trong header, không thêm length field.

**Q5. Mapping opcode → namespace/message_id do ai sở hữu?** (C5)
- (a) bảng tĩnh `Opcode → {ns, mid}`, giữ `opcode_id` nội bộ làm adapter.
- (b) đổi handler registry/bridge/lifecycle sang `(namespace, message_id)`.
- **Lean: (a)** để giảm blast radius; (b) nếu muốn RFC-pure.

**Q6. `intent_id` xử lý sao?** (C6)
- (a) bỏ khỏi wire (giữ trong payload JSON nếu cần correlation).
- (b) giữ như extension (ngoài RFC) để không phá correlation.
- **Lean: (a)** — hiện không được dùng thực chất.

**Q7. Timestamp đơn vị + window?** (C7)
- (a) ns + 300s (RFC 0019).
- (b) ms + 5s (hiện tại).
- **Lean: (a)** theo RFC, nhưng cần đổi đồng bộ toàn bộ chỗ set/parse.

**Q8. Enforce replay ở đâu + state?** (C9)
- Chốt tầng enforce và có/không `SessionSecurityState` (epoch, tx_seq, rx_highest, window).

**Q9. Bind `session_id` vào packet thế nào?** (C10)
- SecureSession có expose session_id? Set ở client khi build packet? Nếu không, replay
  per-session không khả thi.

**Q10. Phạm vi G3 bây giờ?** (C14, C15)
- (a) Chỉ DATA-plane: format header mới + replay + AEAD (theo Q1).
- (b) Cả CONTROL/IDENTITY signature trong Packet layer.
- **Lean: (a)** — CONTROL/IDENTITY đang đi wire format riêng, làm (b) là scope mới.

**Q11. Lifecycle invariant cho epoch/sequence?** (C11, C12)
- Chốt rule cho: epoch rollover, session recovery/restart, persistence, rekey, bidirectional.
- **Đề xuất invariant:** `(session_id, epoch, sequence)` **tuyệt đối không** authenticate 2
  plaintext khác nhau; rekey ⇒ epoch++ và sequence reset; restart ⇒ session invalid (không
  replay được) trừ khi persist epoch+sequence atomically với key.

**Q12. Version?** (C13)
- Chốt `protocol_version` value, có bump `kTransportVersion` không, per-packet hay handshake.

---

## 5. Thứ tự triển khai (sau khi Decision Log §2.5 đã chốt)

1. ~~Ghi lại các quyết định Q1–Q12 vào Decision Log~~ **DONE — §2.5**.
2. Với **Q1=(b)** (làm rõ bởi **B1=(i) §7.1.1**): Packet layer là AEAD owner cho **Packet path**.
   KHÔNG gỡ AEAD khỏi `SecureSession` toàn cục — `send()/recv()` giữ AEAD cho non-Packet CBOR;
   thêm **transport-frame-only** path cho Packet. Định nghĩa `AAD = canonical 39B header`.
3. Sửa `protocol/packet/packet.h/.cpp` (edit tool) theo format đã chốt + mapping Q5.
4. Wire replay (Q8/Q9) + `SessionSecurityState` (Q11).
5. Packet negative tests: replay, stale epoch, tamper, auth-length sai.
6. Full build + ctest + PCT + E2E, rồi cập nhật DISCUSSION_0046 §26.4 và commit/push.

---

## 6. Trạng thái triển khai

Decision Log (§2.5) đã chốt hết Q1–Q12. Blocker B1–B5 cũng đã chốt (§7.1.1):
B1=(i) dual-path, B2=(B2a–B2d), B3=(deterministic KDF from canonical transcript),
B4=(i) `packet_crypto`, B5=(bỏ inner FrameHeader). **P0 + P1 + P2 + P3 DONE**:
canonical `SessionId` + `SessionSecurityState`/`ReplayWindow`, `SessionCryptoContext`
(`PacketTxKey`/`PacketRxKey` opaque, `matches()` CT) + `SecureSession` `session_id` +
`send_framed/recv_framed`, và Packet wire format 39B canonical + `packet_route`
(22/22 ctest, 24/24 PCT). **Tiếp theo: P4** (Packet AEAD `seal_data/open_data`).

Ràng buộc vẫn giữ trong lúc implement:

- KHÔNG double-AEAD chồng `SecureSession` cho **Packet path** (C1) — theo **Q1=(b)**;
  nhưng `SecureSession` **vẫn AEAD** cho non-Packet CBOR (B1=(i), §7.1.1).
- Header `static_assert` trên **39B** (Q2), wire nonce = sequence (Q3), mapping adapter (Q5).
- KHÔNG amend RFC 0019.

---

## 7. Implementation Plan (G3) — chi tiết

> Trạng thái: **plan, chưa code**. Bám đúng Decision Log §2.5. Không amend RFC 0019,
> không tự reconcile thêm. Mọi chỗ §2.5 im lặng → đánh dấu BLOCKER (7.1), không tự quyết.

### 7.0 Guardrails

1. **Không half-old/half-new:** mỗi phase phải `build` + `ctest` xanh trước khi sang phase sau.
2. **Wire change tách khỏi refactor crypto:** format trước (P3), AEAD sau (P4), wiring sau (P5).
3. **Thứ tự receive bắt buộc (§2.5):** parse → session lookup → epoch/window precheck
   → AEAD verify → **commit** replay state → dispatch.
4. **Nonce reuse invariant:** `(session_id, epoch, sequence)` không bao giờ authenticate
   2 plaintext khác nhau; rekey ⇒ `epoch++`, sequence reset.
5. **Suite-ID driven:** không suy luận thuật toán từ độ dài field; `suite_id` → `CryptoRegistry`.

### 7.1 BLOCKERS

> Đây là các điểm §2.5 chưa bao phủ hoặc mâu thuẫn tiềm ẩn. **Không tự quyết.**
> Decision Log cho các blocker đã chốt nằm ở **§7.1.1**.

**B1 — Non-packet traffic (join/enroll) đi đâu?** ✅ *ĐÃ CHỐT (i) — xem §7.1.1*
- `SecureSession` hiện cũng mang CBOR **không phải Packet**:
  - `core/enroll/auto_enroll.cpp:682` `sec.send(req_cbor)` / `:690` `sec.recv()`
  - `cmd/smo-node/main.cpp:1147` mesh-join `sec.send(hello_data)` / `:1155` `sec.recv()`
- Nếu Q1=(b) bị hiểu thành "gỡ AEAD khỏi `SecureSession` toàn cục" → các path này **thành plaintext**
  (security regression).
- **Chốt (i):** giữ `SecureSession::send/recv` AEAD cho non-Packet; thêm **transport-frame-only**
  path cho Packet G3. Chi tiết §7.1.1.

**B2 — K_session expose API?** ⚠️ *hướng đã rõ, chưa chốt API cụ thể*
- Packet AEAD cần `K_session`; `SecureSession` đang giữ private `tx_key_/rx_key_` (`secure_session.hpp:103-104`).
- **KHÔNG** public raw getter kiểu `get_key()` cho cả codebase.
- Hướng chốt: một **key reference/crypto context** có scope rõ ràng
  (`SessionCryptoContext` / key handle) để Packet auth boundary không cần biết internals của `SecureSession`.
- **Cần chốt tên + ownership** (SecureSession vs `SessionSecurityState`).

**B3 — `session_id` derive & expose?** ✅ *ĐÃ CHỐT (invariant + B3a=(b)) — xem §7.1.1*
- Q9 yêu cầu packet mang session_id thật, zero reject; `SecureSession` chưa có session_id.
- **RFC 0019 kiểm tra (2026-08-14):** RFC **KHÔNG** định nghĩa công thức sinh `session_id`
  (chỉ yêu cầu 128-bit + collision resistance) → công thức là **protocol-level definition**,
  ghi trong DISCUSSION này, KHÔNG sửa RFC 0019.
- **B3a đã chốt (b):** deterministic KDF từ transcript handshake đã có sẵn — 2 đầu tự tính khớp,
  không đổi handshake wire. Chi tiết §7.1.1.

**B4 — Vị trí Packet AEAD trong code path?** ✅ *ĐÃ CHỐT hướng (i) — xem §7.1.1*
- **Chốt (i):** tách riêng — `packet.cpp` chỉ serialize/parse canonical bytes;
  crypto + replay nằm ở `packet_crypto`/`packet_auth` (security boundary riêng), gọi giữa
  framing và parse. Không nhồi crypto vào transport.

**B5 — Inner `FrameHeader` (magic `SMO\1`) cho Packet path?** ✅ *ĐÃ CHỐT: BỎ*
- Hiện double framing: `frame_write` (9B) **nằm trong** SecureSession AEAD.
- **Chốt: bỏ inner `FrameHeader` cho Packet path.** `send_framed()/recv_framed()` đã lo
  transport framing (`[length][Packet bytes]`); Packet bên trong chỉ còn
  `[39B header][ciphertext][16B tag]`.
- Lý do: tránh 2 lớp framing chồng nhau, giảm parser state + attack surface, Packet codec
  độc lập với transport.
- `SecureSession` còn: connection + transport framing + non-Packet AEAD.
  *(`FrameHeader` cũ giữ cho non-Packet nếu cần — không đổi path CBOR.)*

### 7.1.1 Blocker Decision Log

**B1 → (i) — CHỐT (2026-08-14):**

> **Preserve `SecureSession.send()/recv()` AEAD semantics for existing non-Packet protocols
> (CBOR join/enroll/etc.). Introduce a separate transport-frame-only Packet path for G3 so
> Packet AEAD is applied exactly once. Do not packetize existing control flows as part of G3.**

Architecture dual-path có chủ đích:

```text
                 SecureSession
        ┌──────────────────────────────┐
        │ handshake                    │
        │ K_session                    │
        │ connection + framing         │
        │                              │
        │ send()/recv()                │
        │   └── vẫn AEAD               │
        │      → CBOR join/enroll      │
        │      → legacy/non-Packet     │
        │                              │
        │ send_framed()/recv_framed()  │
        │   └── framing ONLY           │
        │      → Packet G3              │
        └──────────────┬───────────────┘
                       │
                       ▼
                 Packet G3
             Packet-level AEAD
```

Quy tắc kèm theo (chốt):

- `SecureSession.send()/recv()` **KHÔNG đổi semantic hiện tại** → CBOR join/welcome, enroll sync
  vẫn được AEAD như cũ.
- Thêm API **transport-frame-only** cho Packet G3 (tên gợi ý `send_framed()/recv_framed()`;
  **nghĩa = transport-frame-only, KHÔNG bao gồm Packet AEAD** — Packet codec/auth tự lo AEAD).
- Không packetize CBOR join/enroll chỉ để phục vụ G3.
- Vì B1 tạo **explicit separation**, đây là hướng ít blast radius nhất mà vẫn đúng Q1=(b).

Security invariant của các protocol path đang chạy được giữ nguyên. Điều **cấm** là:

```text
SecureSession.send() bỏ AEAD
    → Packet đúng, nhưng mesh-join CBOR + enroll CBOR thành plaintext  💀
```

**B4 → (i) — CHỐT hướng:** `packet.cpp` thuần serialize/parse; crypto + replay ở
`packet_crypto`/`packet_auth` (security boundary riêng), gọi giữa framing và parse.

**B5 → BỎ inner `FrameHeader` cho Packet path — CHỐT (2026-08-14):**

> Transport framing `[length][Packet bytes]` là đủ; Packet bên trong chỉ còn
> `[39B header][ciphertext][16B tag]`. Không dùng `[length][FrameHeader][39B ...][tag]`.
> `SecureSession` giữ: connection + transport framing + non-Packet AEAD;
> Packet codec giữ: serialization + AEAD + authentication/replay.

**B3 invariant + B3a → (1) — CHỐT (2026-08-14):**

> `session_id` được tạo **đúng một lần** lúc establish session, lưu trong `SessionCryptoContext`
> (một nguồn sự thật). Mọi Packet lấy từ context đó; **`packet.cpp` KHÔNG derive lại**.

Decision wording:

> **B3a → (1) Deterministic KDF from the authenticated handshake transcript. `session_id` is
> derived once from the canonical handshake key-derivation material, truncated to 128 bits,
> and stored in `SessionCryptoContext`. The exact derivation is an implementation/protocol
> profile decision outside RFC 0019. Packet codec MUST NOT derive or recompute `session_id`.
> No handshake wire change is required.**

- RFC 0019 không quy định công thức; formula là **protocol-profile decision** ghi ở DISCUSSION này,
  KHÔNG sửa RFC 0019.
- **Nuance (quant trọng):** tái sử dụng **chính canonical input** mà `derive_keys()` đang dùng,
  KHÔNG tạo định nghĩa transcript concatenation song song. Tránh 2 định nghĩa transcript.
- **Implementation:** tính `session_id` bên trong `derive_keys()` từ cùng `ikm` (đã gồm
  `ss1||ss2||pk_server||pk_client` với salt `"smo-pq-handshake-v1"`), domain-separated
  (ví dụ HKDF `info = "session-id-v1"`), lấy 16B. Cả 2 đầu đã dùng cùng `ikm` nên khớp.
- Không đổi handshake wire, không thêm field/round-trip.

**B2 API — CHỐT boundary (2026-08-14):**

> Packet layer nhận **crypto capability**, KHÔNG nhận raw key. `SecureSession` sở hữu
> handshake-derived secret; `SessionCryptoContext` sở hữu packet crypto capability;
> `packet_crypto` **borrow** capability để thao tác.
>
> - **KHÔNG** có `get_key()` / `key().to_bytes()` trả raw `Bytes` cho cả codebase.
> - **Directional**: tách `tx` / `rx` (client TX == server RX; server TX == client RX).
>   API một `K_session` chung bị cấm vì dễ dùng nhầm orientation.
> - `PacketTxKey`/`PacketRxKey` là **opaque strong type** (private material), không phải alias `Bytes`.

Boundary:

```text
SecureSession ──(authenticated handshake)──▶ SessionCryptoContext
                                                ├── SessionId
                                                ├── PacketTxKey
                                                └── PacketRxKey
                                                         │ borrow
                                                         ▼
                                                   packet_crypto
```

**B2a–B2d — CHỐT (2026-08-14):**

> **B2a → (1)** Directional `PacketTxKey` and `PacketRxKey` are distinct types.
> **B2b → (1)** Provide constant-time `matches()` for P2 orientation verification without
> exposing raw key material.
> **B2c → (1)** `SessionCryptoContext` lives under `core/session/`.
> **B2d → (1)** Remove `session_key: Bytes` from `SessionSecurityState`; crypto material is
> owned by `SessionCryptoContext`.

API shape chốt:

```cpp
class PacketTxKey {
public:
    bool valid() const noexcept;
    bool matches(const PacketRxKey& other) const noexcept;  // constant-time
private:
    Bytes material_;                                        // opaque
    friend class SessionCryptoContext;
    friend class PacketRxKey;
};

class PacketRxKey {
public:
    bool valid() const noexcept;
private:
    Bytes material_;                                        // opaque
    friend class SessionCryptoContext;
    friend class PacketTxKey;                               // để matches() đọc được
};

class SessionCryptoContext {
public:
    const SessionId& session_id() const noexcept;
    const PacketTxKey& packet_tx_key() const noexcept;      // borrow, không copy
    const PacketRxKey& packet_rx_key() const noexcept;      // borrow, không copy
private:
    SessionId session_id_;
    PacketTxKey tx_key_;
    PacketRxKey rx_key_;
};
```

- **Không có** `Bytes key()`, `BytesView key()`, `const uint8_t* raw_key()`.
- *Implementation note:* key là opaque + move-only → getter trả `const&` (borrow),
  đúng tinh thần "packet_crypto borrows capability". `matches()` dùng constant-time compare.

`SessionSecurityState` sau B2d (không còn secret):

```cpp
SessionSecurityState {
    SessionId session_id;
    uint64_t epoch;
    uint64_t tx_sequence;
    uint64_t rx_epoch;
    ReplayWindow rx_window;
};
```

Tách ownership:

```text
Session
├── SessionCryptoContext   (secret owner)
│   ├── SessionId
│   ├── PacketTxKey
│   └── PacketRxKey
│
└── SessionSecurityState    (state-only, KHÔNG giữ secret)
    ├── epoch
    ├── tx_sequence
    ├── rx_epoch
    └── replay_window
```

**P2 exit criteria (chốt):**
1. `SecureSession::send()/recv()` không đổi semantic.
2. `send_framed()/recv_framed()` chỉ framing (KHÔNG AEAD).
3. `SessionCryptoContext` expose `session_id` + directional packet capability.
4. Không public raw-key getter.
5. `session_id` derive đúng một lần từ canonical handshake `ikm`.
6. Hai endpoint cùng `SessionId`.
7. Client TX ↔ Server RX key match.
8. Server TX ↔ Client RX key match.
9. CBOR `send()/recv()` regression test vẫn AEAD.
10. Chưa wire Packet G3 vào CLI/node.

**Tổng blocker:** ✅ **TẤT CẢ ĐÃ CHỐT.** B1=(i), B2=(B2a–B2d), B3=(deterministic KDF),
B4=(i), B5=(bỏ inner FrameHeader). **Đủ điều kiện P2.**

**SessionId canonicalization — CHỐT & DONE (pre-P2, 2026-08-14):**

- **Vấn đề:** 2 định nghĩa `smo::SessionId` — `core/session/session.h` (plain, dùng bởi
  storage/ACL) và `core/session/session.hpp` (superset có `derive/to_bytes/from_bytes/to_hex`,
  dùng bởi Session/SessionManager). Latent type-duplication, cùng semantic.
- **Chốt:** tách canonical primitive `core/session/session_id.hpp` (+`.cpp`) làm **một nguồn
  sự thật duy nhất**; `session.h` và `session.hpp` đều include nó. `bytes` giữ public để tránh
  phá call sites (storage dùng `id.bytes`).
- **Invariant:** handshake/`derive_keys()` → `SessionCryptoContext` (`SessionId` + material)
  → `SessionSecurityState` dùng lại → packet header `session_id`. **Không** `packet.cpp`
  derive/compute lại; **không** có 2 nơi cùng tính rồi assert bằng nhau.
- **Trạng thái:** DONE — còn đúng 1 `struct SessionId`; 21/21 ctest + 24/24 PCT xanh.
- *(Lưu ý: `Session` vẫn còn 2 phiên bản — `session.h` struct vs `session.hpp` class. Ngoài
  scope G3; chưa có TU nào include cả hai.)*

### 7.2 Kiến trúc & wire format đích (sau Q1(b), B1=(i))

Dual-path có chủ đích (mỗi lớp traffic đúng **một** AEAD):

```text
                SecureSession
               /             \
      legacy/control        Packet G3
            │                   │
        AEAD hiện tại       Packet AEAD
            │                   │
          frame               frame
             \                 /
                    TCP
```

Phân tầng trách nhiệm:

```text
Application
    ├── Control / Join / Enroll → SecureSession → transport AEAD → framing
    └── Packet → packet.cpp (39B canonical) → packet_crypto (AEAD + replay)
                    → SecureSession frame-only → TCP
```

```text
TCP stream  : [4B total_len][ Packet ]
                (transport-frame-only path — KHÔNG SecureSession AEAD cho Packet)
Packet      : [39B header (cleartext, AAD)][ciphertext N][16B AEAD tag]
              header.session_id  → session lookup
              header.nonce       → sequence (monotonic)
              nonce24            = BLAKE3(session_id || nonce8)[0:24]
              AAD                = canonical 39B header
```

Security state:

```text
Session
 └── SessionSecurityState
      ├── session_id
      ├── K_session          (qua SessionCryptoContext — B2)
      ├── epoch
      ├── tx_sequence
      ├── rx_epoch
      ├── rx_highest
      └── replay_window
```

### 7.3 File-by-file change map

| File | Thay đổi | Phase |
|---|---|---|
| `core/session/session_id.hpp/.cpp` *(mới)* | canonical `SessionId` primitive; migrate `session.h` + `session.hpp` | **P1 DONE** |
| `core/session/session_security.hpp/.cpp` *(mới)* | `SessionSecurityState`, `ReplayWindow` | P1 |
| `core/session/session.hpp/.cpp` | dùng canonical `SessionId`; gắn `SessionSecurityState` | P1/P2 |
| `core/session/session_crypto_context.hpp/.cpp` *(mới)* | `SessionCryptoContext`, `PacketTxKey`, `PacketRxKey` (opaque, `matches()` CT) — **B2** | **P2 DONE** |
| `core/transport/secure_session.hpp/.cpp` | `send()/recv()` **giữ nguyên AEAD**; thêm transport-frame-only `send_framed/recv_framed`; derive `session_id` một lần trong `derive_keys()`; expose `SessionCryptoContext` (B1/B2) | **P2 DONE** |
| `protocol/packet/packet.h/.cpp` | header canonical 39B + codec big-endian + compat shim | P3 **DONE** |
| `protocol/packet/packet_route.hpp/.cpp` *(mới)* | mapping `Opcode ↔ {namespace,message_id}` | P3 **DONE** |
| `protocol/packet/packet_crypto.hpp/.cpp` *(mới)* | `seal_data/open_data` + derive nonce24 (B4=(i): tách khỏi `packet.cpp`) | P4 |
| `cmd/smo-cli/cli_context.cpp` | build packet (ns/mid, session_id, ts ns, seq), seal, send_framed | P5 |
| `cmd/smo-node/main.cpp` | open_data trước dispatch; response seal + session_id | P5 |
| `core/network/packet_dispatcher.cpp` | route theo `(namespace,message_id)`/adapter; bỏ inner frame — **B5 đã chốt** | P5 |
| `core/runtime/runtime_bridge.cpp` | giữ nguyên (adapter `opcode_id`) — Q5(a) | — |
| `transport/tcp/tcp_transport.cpp` (hl, test path) | cập nhật theo format mới | P5 |
| `protocol/replay/replay.*` | thay bằng per-session `ReplayWindow` (hoặc deprecate) | P1 |
| `tests/unit/protocol/test_protocol.cpp`, `test_pct.cpp` | cập nhật + negative tests | P3-P7 |

### 7.4 Phases

#### P0 — Pre-flight
- ✅ Blocker đã chốt hết (B1=(i), B3=(deterministic KDF from canonical transcript), B4=(i),
  B5=(bỏ inner FrameHeader); B2 API shape quyết trong P1/P2) — §7.1.1.
- Baseline: `build` + `ctest` (20) + `PCT` (24) xanh, ghi lại số.
- **Exit:** mọi blocker có câu trả lời ghi vào §7.1.1.

#### P1 — canonical `SessionId` + `SessionSecurityState` + `ReplayWindow` (không đổi wire) — ✅ DONE

**P1a — canonical `SessionId` (pre-P2 blocker):**
- Tạo `core/session/session_id.hpp/.cpp` (canonical primitive); `session.h` + `session.hpp`
  include nó; xóa 2 định nghĩa cũ. `bytes` giữ public.
- **Exit:** còn đúng 1 `struct SessionId`.

**P1b — security state:**
- Thêm `core/session/session_security.hpp/.cpp`:

```cpp
struct SessionSecurityState {
    SessionId session_id{};   // canonical type
    uint64_t epoch{0};
    uint64_t tx_sequence{0};
    uint64_t rx_epoch{0};
    ReplayWindow rx_window;   // per (session_id, epoch)
    // KHÔNG có key ở đây — secret thuộc SessionCryptoContext (B2d)
};

class ReplayWindow {          // window = 64 bit
public:
    bool is_acceptable(uint64_t seq) const; // precheck, KHÔNG mutate
    bool commit(uint64_t seq);              // chỉ gọi sau AEAD success
private:
    uint64_t highest_{0};
    uint64_t bitmap_{0};
};
```

- Unit tests: seq 1..N accept; duplicate reject; cũ hơn window reject; `commit` chỉ sau precheck;
  rekey (`epoch++`) reset window.
- **Exit:** build + test mới xanh; chưa nối vào path nào.
- **Kết quả:** 9 test PASS (`smo_test_session_security`, ctest `session_security_model`),
  21/21 ctest + 24/24 PCT xanh.

#### P2 — `SessionCryptoContext` + `SecureSession` frame-only path (theo B1=(i)/B2/B3)
- `send()/recv()` **KHÔNG đổi semantic** (vẫn AEAD) → non-Packet CBOR an toàn.
- Thêm transport-frame-only `send_framed/recv_framed` (**frame-only, KHÔNG Packet AEAD**) cho G3.
- Thêm `core/session/session_crypto_context.hpp/.cpp`: `SessionCryptoContext` +
  `PacketTxKey`/`PacketRxKey` (opaque, move-only, `matches()` constant-time) — B2a–B2c.
- Bỏ `session_key: Bytes` khỏi `SessionSecurityState` (B2d); context là secret owner.
- `SecureSession`: derive `session_id` **một nơi** trong `derive_keys()` từ cùng canonical
  `ikm` (domain-separated, 16B) — B3a=(1); build `SessionCryptoContext` sau handshake
  (client: sau derive; server: sau `swap`) → client TX == server RX.
- Test: hai endpoint cùng `session_id`; `client.tx.matches(server.rx)` và
  `server.tx.matches(client.rx)`; `!client.tx.matches(client.rx)`; regression CBOR
  `send/recv` vẫn AEAD.
- **Exit:** build + ctest + PCT xanh; Packet path **chưa** wire (vẫn dùng `send/recv` cũ);
  10 exit criteria §7.1.1 B2 pass.
- **Kết quả (DONE):** `core/session/session_crypto_context.{hpp,cpp}` mới
  (`SessionCryptoContext`, `PacketTxKey`/`PacketRxKey` opaque move-only, `matches()` CT,
  không raw getter). `session_id` HKDF 16B, cùng `ikm`+salt `smo-pq-handshake-v1`,
  `info = "session-id-v1"`, derive **một lần** trong `derive_keys()`; context build sau
  handshake (sau `swap` ở server). Bỏ `session_key` khỏi `SessionSecurityState`.
  `send_framed/recv_framed` = `[4B BE len][payload]` framing-only. Test mới
  `smo_test_secure_session` (ctest `secure_session_model`) **7/7 PASS**: handshake 2 đầu,
  shared `session_id`, orientation (tx/rx chéo khớp + tự cặp khác), CBOR `send/recv` vẫn
  AEAD, framed roundtrip, framed **plaintext** (đọc raw socket), reject trước handshake.
  **22/22 ctest + 24/24 PCT xanh.** 10/10 exit criteria đạt; chưa wire Packet G3.

#### P3 — Packet format 39B + route mapping (chưa AEAD)

> **Quyết định P3 #1 — Route mapping (Q5), chốt 2026-09-17: "option 4 — RFC-pure".**
> Không tạo namespace mới ngoài 0x01–0x04 (không dùng 0x05/0x06 dù codebase
> bootstrap/join hiện đang gộp namespace+method vào một `opcode_id` 32-bit).
> `message_id` = **giá trị byte của `Opcode` nội bộ** (implementation mapping,
> **không** phải RFC registration). Packet-capable (25 opcode):
> - `0x03 EXECUTION`: LS, PUT, GET, EXEC, QUARANTINE, MKDIR, RM, CP, ECHO, FILE_OP, PROCESS, CUSTOM
> - `0x02 CONTROL`: CONTRACT_MGMT, WITNESS, REVOKE_CERT, EPOCH_INCREMENT, RECOVERY_SESSION, CRL_SYNC, RECOVERY, GOV_PROPOSE, GOV_VOTE, GOV_COMMIT, GOV_LIST, GOV_STATUS, GOV_INFO
> - **Non-Packet (không có route, reject):** BOOTSTRAP_SNAPSHOT, BOOTSTRAP_INFO, JOIN, LEAVE, JOIN_INFO.
> - Test T7: roundtrip cho mọi Opcode packet-capable; assert non-Packet không có route.

> **Quyết định P3 #2 — Packet struct compat shim (Q6), chốt 2026-09-17: "option 1".**
> "P3 preserves legacy `Packet` fields as in-memory compatibility adapters only. They are
> explicitly non-wire fields and MUST NOT participate in serialization, authentication/AAD,
> equality of canonical wire representation, or packet-size calculations."
> `session_id`/`timestamp` là canonical trong `PacketHeader`, **không** tạo duplicate field;
> `Packet` cung cấp accessor `session_id()`/`timestamp()` trỏ vào header. Shim `opcode_id`/
> `intent_id` sẽ bị xóa ở P5 khi caller được migrate.

- `packet.h`:

```cpp
struct PacketHeader {              // in-memory; wire ghi big-endian từng field
    uint8_t  protocol_version{0x03};
    uint8_t  suite_id{0};
    uint8_t  ns{0};                // 'namespace' là keyword C++, đặt là 'ns'
    uint16_t message_id{0};
    uint8_t  session_id[16]{};
    int64_t  timestamp{0};         // Unix ns (int64 để khớp caller cũ)
    uint64_t nonce{0};             // = sequence
    uint16_t payload_length{0};
};
inline constexpr size_t kPacketHeaderWireSize = 1+1+1+2+16+8+8+2; // 39
static_assert(kPacketHeaderWireSize == 39);
```

> Lưu ý: struct **không** `packed` — packed field không bind được vào reference mà
> accessor canonical cần; codec tự ghi/đọc big-endian nên `sizeof(struct)` không
> tham gia wire. Kích thước wire được assert qua `kPacketHeaderWireSize`.

- `Packet { PacketHeader header; Bytes payload; Bytes auth; }` + accessor
  `session_id()`/`timestamp()` (map vào header); shim in-memory `opcode_id`, `intent_id`
  (không lên wire, không tham gia AAD/size/equality). `signature[64]` bị bỏ.
- `packet_route`: bảng tĩnh `Opcode → {ns, mid}`; `to_packet_route/from_packet_route` (Q5);
  `expected_auth_length(ns, suite_id)` derive signature/AEAD-tag size (Q4, không lên wire).
- `packet_from_buffer`: reject version ≠ 0x03; reject nonce == 0 (RFC rule 1); reject zero
  session_id (Q9); reject namespace ngoài 0x02/0x03/0x04; bounds-check payload/auth length.
- Unit tests: roundtrip 39B; bad version; zero nonce; zero session_id; payload_length mismatch;
  auth-length sai/thiếu; mapping roundtrip toàn bộ `Opcode`.
- **Exit:** build + protocol tests xanh (chưa AEAD, chưa wiring).

**P3 — ✅ DONE (2026-09-17).**
- `packet.h/.cpp`: header canonical (unpacked in-memory; wire 39B ghi big-endian từng field,
  `kPacketHeaderWireSize` + `static_assert==39`); `Packet{header,payload,auth}` + accessor
  `session_id()/timestamp()` + shim `opcode_id/intent_id`; bỏ `signature[64]`.
- `expected_auth_length(ns, suite_id)`: EXECUTION/DATA = 16 (AEAD tag); CONTROL suite 1/2 = 64,
  suite 3 = 3309; còn lại = 0 → reject "unsupported namespace".
- `packet_route.hpp/.cpp`: 25 opcode packet-capable (12 EXECUTION + 13 CONTROL), 5 non-Packet
  (BOOTSTRAP_*/JOIN/LEAVE/JOIN_INFO) không có route; `message_id = opcode byte`.
- `packet_from_buffer` reject: version≠0x03, <39B, nonce==0, zero session_id, ns ngoài
  0x02/0x03/0x04, payload_length vượt buffer, auth length sai/thiếu.
- `packet_to_buffer`: derive route từ `opcode_id` khi `header.message_id==0`; reject
  non-Packet opcode.
- Caller tối thiểu (canonical accessor, không wiring): `cli_context.cpp`, `main.cpp` (2 chỗ),
  `action_executor.cpp`, `bootstrap_protocol.cpp` (chỉ compile-fix), 2 test transport.
- Tests T1–T7 trong `tests/unit/protocol/test_protocol.cpp` PASS; **22/22 ctest, 24/24 PCT**.

#### P4 — Packet AEAD `seal_data/open_data` (DATA plane, Q10)
- `packet_crypto` (B4=(i)):

```cpp
Bytes derive_aead_nonce(BytesView session_id, uint64_t wire_nonce); // BLAKE3[0:24]
Result<void> packet_seal_data(Packet&, BytesView key, uint64_t sequence);
Result<void> packet_open_data(Packet&, BytesView key);  // verify+decrypt
```

- AAD = canonical 39B header (serialize header với `payload_length` đã set, nonce đã set).
- **Ràng buộc cứng:** `packet_crypto` chỉ nhìn canonical 39B header → AAD; **KHÔNG** biết và
  **KHÔNG** phụ thuộc `opcode_id`/`intent_id` (shim P3). Mapping `opcode_id → {ns, message_id}`
  chỉ thuộc `packet_route`/adapter. `packet_crypto` không gọi `packet_route`.
- `packet_open_data` fail ⇒ **không** commit replay state.
- Unit tests: seal→open roundtrip; tamper payload → fail; tamper header (AAD) → fail;
  sai key → fail; tag 16B; nonce derive khớp 2 đầu.
- **Exit:** build + tests xanh.

#### P5 — Wiring vào CLI + Node + Dispatcher
- `cli_context.cpp`: dựng header (ns/mid từ opcode, session_id thật, timestamp ns, nonce=seq
  từ `SessionSecurityState`), `packet_seal_data`, `send_framed`.
- `main.cpp`:
  - `dispatch_session` path: parse → lookup session theo header session_id → open_data →
    dispatch.
  - `runtime_handler`: bỏ phụ thuộc `opcode_id`/`intent_id` thô; dùng adapter.
  - Response: set session_id + seal_data + `send_framed`.
- `packet_dispatcher.cpp`: route key theo adapter `(ns,mid) → Opcode`; **bỏ inner `frame_write`
  cho Packet path (B5 đã chốt)**; lifecycle check dùng adapter.
- `hl::TcpTransport` (test path): cập nhật.
- E2E test 1 packet CLI↔node xanh.
- **Exit:** build + ctest + PCT + E2E xanh.

#### P6 — Wire replay enforcement + ordering
- Trong receive path: `parse → session lookup → epoch/window precheck (is_acceptable)
  → packet_open_data → commit → dispatch`.
- `ReplayProtector` cũ (test-only) deprecate/đổi thành `ReplayWindow` per-session.
- Test: replay dup seq reject; stale epoch reject; advance state chỉ khi AEAD success
  (gửi packet giả seq cao → không đẩy `highest`).
- **Exit:** xanh.

#### P7 — Packet negative tests + PCT
- Negative: replay, stale epoch, tamper payload, tamper header/AAD, auth length sai,
  zero nonce, zero session_id, version sai, suite_id hỏng.
- PCT + E2E 3-node (DISCUSSION_0045 scenario).
- **Exit:** PCT-full xanh.

#### P8 — Docs + commit/push
- Cập nhật DISCUSSION_0046 §26.4 (G3 done), §15 status; cross-link 0047.
- Không amend RFC 0019.
- commit + push (chỉ khi anh yêu cầu).

### 7.5 Test matrix (tối thiểu)

| # | Case | Expect |
|---|---|---|
| T1 | Header roundtrip 39B | pass |
| T2 | version ≠ 0x03 | reject |
| T3 | nonce == 0 | reject |
| T4 | session_id == 0 | reject |
| T5 | payload_length mismatch | reject |
| T6 | auth length sai/thiếu | reject |
| T7 | `Opcode ↔ {ns,mid}` roundtrip | pass |
| T8 | seal→open roundtrip | pass |
| T9 | tamper payload | auth fail |
| T10 | tamper header (AAD) | auth fail |
| T11 | duplicate sequence (replay) | reject |
| T12 | stale epoch | reject |
| T13 | fake high seq không advance state | state unchanged |
| T14 | rekey: epoch++, seq reset | tuple unique, accept |
| T15 | restart: session Closed | packet cũ reject |

### 7.6 Verification commands

```text
cmake --build build -j            # hoặc build dir hiện hành
ctest --test-dir build            # hiện 20 tests
./build/tests/smo_pct             # hiện 24 PCT
# + E2E scenario DISCUSSION_0045
```

*(Xác nhận lại tên target/path build trước khi chạy.)*

### 7.7 Risks & rollback

| Risk | Mitigation |
|---|---|
| Half-old/half-new (join/enroll plaintext) | P0 chốt B1; không merge P2 khi B1 chưa rõ |
| Nonce reuse sau restart/rekey | P1 invariant + T14/T15 |
| AAD mismatch CLI↔node | canonical header serialize dùng chung 1 hàm |
| Version lệch (`0x03` vs framing `1`) | Q12: giữ độc lập, không đánh đồng |
| Blast radius `SecureSession` | B1 tách path; test handshake 2 đầu ở P2 |
| Performance (Packet AEAD per-message) | đo trước/sau ở P5 |

Rollback: mỗi phase là 1 commit độc lập; P3/P4 không wire nên revert an toàn.

### 7.8 Out of scope

- CONTROL/IDENTITY signature trong Packet (Q10=(a)).
- Amend RFC 0019.
- Rewrite dispatcher/runtime (Q5=(a) adapter).
