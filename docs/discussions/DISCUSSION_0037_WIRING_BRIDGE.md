# DISCUSSION 0037 — Wiring Bridge: Nối Transport + RuntimeKernel + Contracts

**Tác giả:** Nguyen Duc Canh + DeepSeek
**Ngày:** 2026-07-18
**Trạng thái:** Draft — chờ review

---

## Nhận định

Transport đã chạy, Runtime đã chạy, Contracts đã chạy — nhưng hai khối chưa được nối với nhau. Đây là trạng thái rất thường gặp ở các framework runtime.

## Pipeline mục tiêu

```
                    NETWORK
              ┌────────────────┐
              │ TCP Listener   │
              │ UDP Listener   │
              └───────┬────────┘
                      │
          recv()/send()/heartbeat
                      │
              PacketDispatcher
                      │
          lookup opcode handler
                      │
          Packet -> RuntimeRequest
                      │
              RuntimeKernel
                      │
           Dispatcher / PlanExecutor
                      │
          Contract::execute(...)
                      │
             ContractResult
                      │
             NextActions
          ┌───────────┴────────────┐
          │                        │
    Dispatch Packet         Dispatch Contract
          │                        │
     TCP/UDP send            RuntimeKernel
```

## Hiện trạng

```
TCP/UDP             ✓
Packet Parser       ✓
Packet Dispatcher   ✓
RuntimeKernel       ✓
Contracts           ✓

NHƯNG

PacketDispatcher
      │
      X
RuntimeKernel
```

Thiếu đúng cầu nối (bridge) giữa `PacketDispatcher` và `RuntimeKernel`.

---

## Luồng thực tế nếu hoàn thiện

### 1. Node A khởi động

```
main()
  → load config
  → Identity
  → Vault
  → Crypto
  → Transport
  → RuntimeKernel
  → Register NativeContracts
  → listen TCP
  → listen UDP
```

Node Ready.

---

### 2. Join mesh

```bash
smo join
```

CLI tạo `RuntimeRequest`:

```
contract = system.join
method   = join
arguments: { mesh_id, seed, certificate }
```

→ RuntimeKernel → Dispatcher → JoinContract

JoinContract quyết định:
- Bootstrap
- Handshake
- Identity verify
- Network send

---

### 3. JoinContract gửi BOOTSTRAP_REQUEST

JoinContract sinh `ActionDispatchMessage`:

```
opcode = BOOTSTRAP_REQUEST
payload = { nonce, node_id, cert_fingerprint }
```

→ RuntimeKernel → TransportAdapter → TCP send() → Seed Node

---

### 4. Seed nhận packet

```
TCP → PacketDispatcher → Opcode = BOOTSTRAP_REQUEST
```

**Đây chính là đoạn còn thiếu.**

Thay vì `handler(packet)`, nó phải chuyển thành:

```
RuntimeRequest req
req.contract = "system.bootstrap"
req.method   = "bootstrap_request"
req.arguments = ...
```

→ RuntimeKernel.execute() → BootstrapContract → ContractResult → ActionDispatchMessage → BOOTSTRAP_RESPONSE → TCP send()

---

### 5. Node A nhận response

```
TCP → PacketDispatcher → RuntimeRequest → BootstrapContract
  → ContractResult → NextAction::DispatchContract → system.join
  → JoinContract tiếp tục
    → Identity verify
    → Membership update
    → Audit
    → Success
```

---

## Heartbeat

```
UDP packet → PacketDispatcher → HeartbeatContract
  → update peer
  → metrics
  → audit
```

Không cần main loop xử lý gì cả.

---

## Governance

```
CLI: proposal submit
  → GovernanceContract
    → ActionDispatchMessage → broadcast proposal

Mọi node:
  → PacketDispatcher → GovernanceContract → vote
    → ActionDispatchMessage → broadcast vote
      → GovernanceContract → quorum → commit
```

---

## Recovery

```
CLI: recover
  → RecoveryContract
    → Vault → Crypto → Identity
    → ActionDispatchMessage → broadcast recovery notice
```

---

## FileContract

```
CLI: put a.iso
  → FileContract
    → chunk → ActionDispatchMessage → Transport → remote
      → PacketDispatcher → FileContract → Storage
```

---

## ProcessContract

```
CLI: run backup.plan
  → ProcessContract
    → PlanExecutor
      → JoinContract → FileContract → GovernanceContract → RecoveryContract
        → ActionDispatch... → Done
```

---

## Kết luận: Bước tiếp theo là Wiring, không phải Test

Hiện tại các thành phần giống như những mảnh LEGO đã hoàn chỉnh:

| Module | Trạng thái |
|--------|------------|
| TCP/UDP Transport | ✅ |
| Packet + Framing | ✅ |
| PacketDispatcher | ✅ |
| RuntimeKernel (8 stages) | ✅ |
| Dispatcher | ✅ |
| Native Contracts (6) | ✅ |
| PlanExecutor + NextAction | ✅ |
| **Bridge PacketDispatcher ↔ RuntimeKernel** | **❌** |

Nếu viết unit test lúc này, bạn chỉ kiểm tra từng khối riêng lẻ mà chưa chứng minh được luồng thực tế hoạt động.

### Thứ tự ưu tiên

1. **Wiring**: `PacketDispatcher ↔ RuntimeKernel ↔ NativeContracts ↔ TransportAdapter` để tạo luồng xử lý hoàn chỉnh.
2. **Integration tests**: chạy các kịch bản như Join, Bootstrap, Heartbeat, Governance giữa 2–3 node để xác nhận toàn bộ pipeline.
3. **Unit tests**: bổ sung cho từng contract và từng service riêng lẻ.
4. Sau khi có một hệ thống chạy end-to-end ổn định mới chuyển sang **Sprint 37** với các tính năng mới.

Đó là thứ sẽ biến framework từ "đã implement đủ module" thành "một mesh network thực sự có thể giao tiếp và thực thi contract".
