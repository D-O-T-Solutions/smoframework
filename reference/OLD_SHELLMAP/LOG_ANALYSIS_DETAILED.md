# DETAILED LOG ANALYSIS - ShellMap

## SECTION 1: LOGS REQUIRING SUPPRESSION

### Category 1.1: [DISPATCH] Logs (NAT Address Updates)

| Line | File | Function | Log Content | Frequency | Issue |
|------|------|----------|-------------|-----------|-------|
| 57 | ProtocolManager.cpp | dispatch_packet() | `"[DISPATCH] Peer address updated (possibly Symmetric NAT)"` | Very High (triggered on every address change) | Fills console during normal NAT operations |

**Context:**
```cpp
Lines 54-59:
    bool addr_changed = update_peer_address(sender_id_str, std::string(sender_ip), sender_port);
    if (addr_changed && (hdr.op_code != OpCode::HELLO && hdr.op_code != OpCode::WELCOME && hdr.op_code != OpCode::AUTH)) {
        // Only log address changes for non-handshake packets
        std::cout << "[DISPATCH] Peer address updated (possibly Symmetric NAT)" << std::endl;
    }
```

**Recommendation:** Comment out line 57 OR implement rate limiting (only log once per peer)

---

### Category 1.2: Orphaned Heartbeat Logs

| Line | File | Function | Log Content | Issue |
|------|------|----------|-------------|-------|
| 1512-1513 | ProtocolManager.cpp | send_heartbeat_pings() | `" (" << (time_since_ping / 1000000000ULL) << "s). Ping count: " << (int)session->ping_sent_count << "/3"` | Missing prefix - parent line 1511 is commented |
| 1519 | ProtocolManager.cpp | send_heartbeat_pings() | `" - No response after 3 PINGs (45s)"` | Missing prefix - parent line 1518 is commented |

**Context for 1512-1513:**
```cpp
Lines 1509-1513:
    if (time_since_ping > PING_TIMEOUT) {
//        std::cout << "[HEARTBEAT] WARNING: No PING_ACK for " << node_id.substr(0, 8);  // <-- COMMENTED
        std::cout << " (" << (time_since_ping / 1000000000ULL) << "s). Ping count: ";   // <-- ORPHANED
        std::cout << (int)session->ping_sent_count << "/3" << std::endl;                // <-- ORPHANED
```

**Context for 1519:**
```cpp
Lines 1517-1519:
    if (session->ping_sent_count >= 3) {
//        std::cout << "[HEARTBEAT] TIMEOUT: " << node_id.substr(0, 8);  // <-- COMMENTED
        std::cout << " - No response after 3 PINGs (45s)" << std::endl;   // <-- ORPHANED
```

**Recommendation:** Either:
- **Option A:** Remove lines 1512-1513, 1519 entirely
- **Option B:** Uncomment lines 1511, 1518 to restore complete messages

---

### Category 1.3: All PING-Related Active Logs

**Error/Warning logs (should keep for debugging):**

| Line | Severity | Content |
|------|----------|---------|
| 539 | stderr | `"[PROTOCOL] Invalid PING payload size"` |
| 583 | stderr | `"[PROTOCOL] No session for PING sender: " << sender_id_str` |
| 1344 | stderr | `"[PROTOCOL] Failed to send PING packet"` |
| 1555 | stderr | `"[HEARTBEAT] Failed to send PING to " << node_id.substr(0, 8)` |
| 1600 | stderr | `"[PROTOCOL] Cannot send PING_ACK: no session for " << node_id` |
| 1620 | stderr | `"[PROTOCOL] Failed to send PING_ACK"` |

**Commented PING logs (already suppressed):**

| Line | Content | Should Keep? |
|------|---------|--------------|
| 535 | `"[PROTOCOL] PING from "` | No - verbose |
| 558 | `"[PROTOCOL] Pong! (" << rtt_ms << " ms)"` | Maybe - useful for latency debugging |
| 581 | `"[PROTOCOL] PING (pong) sent to "` | No - verbose |
| 1309 | `"[PROTOCOL] Sending PING to " << target_ip << ":" << target_port` | No - verbose |
| 1348 | `"[PROTOCOL] PING sent to " << target_ip << ":" << target_port << " (ts="` | No - verbose |
| 1552 | `"[HEARTBEAT] PING sent to " << node_id.substr(0, 8)` | No - verbose |
| 1624 | `"[PROTOCOL] PING_ACK sent to " << node_id.substr(0, 8)` | No - verbose |

**CommandHandler PING logs (user-facing):**

| Line | Content | Status |
|------|---------|--------|
| 409 | `"[PING] Sending to " << target_ip << ":" << target_port` | Keep (user initiated) |
| 413 | `"✗ Failed to send PING"` | Keep (error reporting) |
| 419 | `"[PING] Waiting for response..."` | Keep (user feedback) |

---

## SECTION 2: FILE OPERATIONS - DETAILED STATUS

### 2.1 cmd_ls() Implementation

**Status:** ✓ FULLY IMPLEMENTED ON CLIENT SIDE (REQUEST)

| Aspect | Location | Status | Details |
|--------|----------|--------|---------|
| **Request building** | Line 520-527 | ✓ Complete | Encodes `[path_len (2 bytes)][path]` |
| **Packet creation** | Line 530-537 | ✓ Complete | Creates FS_LIST_REQ packet with proper opcode |
| **Encryption** | Line 547 | ✓ Complete | Uses session AES-256-GCM |
| **Network send** | Line 548 | ✓ Complete | Sends via network engine |
| **Response handling** | Line 825 | ✗ EMPTY STUB | Needs implementation |

**Server Side Handler:** `handle_fs_list_req()` Line 724
- Status: ✓ Fully implemented
- Decrypts request, lists files from `shellmap/shared/[path]`
- Returns format: `count[2 bytes] + "name1\|size1\|type1;name2\|size2\|type2;..."`
- Sends FS_LIST_RES encrypted

**Missing Implementation:**
```cpp
Line 825:
void ProtocolManager::handle_fs_list_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_LIST_RES" << std::endl;
}
```

---

### 2.2 cmd_get() Implementation

**Status:** ✓ FULLY IMPLEMENTED ON CLIENT SIDE (REQUEST)

| Aspect | Location | Status | Details |
|--------|----------|--------|---------|
| **Request building** | Line 581-588 | ✓ Complete | Encodes `[filename_len (2 bytes)][filename]` |
| **Packet creation** | Line 591-598 | ✓ Complete | Creates FS_DATA_REQ packet |
| **Encryption** | Line 607 | ✓ Complete | Uses session AES-256-GCM |
| **Network send** | Line 608 | ✓ Complete | Sends via network engine |
| **Response handling** | Line 997 | ✗ EMPTY STUB | Needs implementation |

**Server Side Handler:** `handle_fs_data_req()` Line 906
- Status: ✓ Fully implemented
- Decrypts filename, reads from `shellmap/shared/[filename]`
- Returns format: `[file_size (8 bytes)][file_data...]`
- Error: Returns single byte `0xFF` if file not found

**Missing Implementation:**
```cpp
Line 997:
void ProtocolManager::handle_fs_data_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_DATA_RES" << std::endl;
}
```

---

### 2.3 cmd_put() Implementation

**Status:** ✓ FULLY IMPLEMENTED ON CLIENT SIDE (REQUEST)

| Aspect | Location | Status | Details |
|--------|----------|--------|---------|
| **File validation** | Line 642-648 | ✓ Complete | Checks file exists, gets size |
| **Request building** | Line 650-660 | ✓ Complete | Encodes `[filename_len (2)][filename][file_size (8 bytes)]` |
| **Packet creation** | Line 663-670 | ✓ Complete | Creates FS_PUT_META_REQ packet |
| **Encryption** | Line 679 | ✓ Complete | Uses session AES-256-GCM |
| **Network send** | Line 680 | ✓ Complete | Sends via network engine |
| **Response handling** | Line 1073 | ✗ EMPTY STUB | Needs implementation |
| **Data upload** | ✗ NOT IMPLEMENTED | ✗ Missing | No FS_PUT_DATA sending logic |

**Server Side Handlers:**
- `handle_fs_put_meta_req()` Line 1001 - ✓ Complete (validates and returns approval)
- `handle_fs_put_data()` Line 1077 - ✓ Complete (receives chunks, writes to disk)

**Missing Implementations:**
```cpp
Line 1073:
void ProtocolManager::handle_fs_put_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_PUT_META_RES" << std::endl;
}
```

---

### 2.4 cmd_cd() Implementation

**Status:** ✓ FULLY IMPLEMENTED ON CLIENT SIDE (REQUEST)

| Aspect | Location | Status | Details |
|--------|----------|--------|---------|
| **Request building** | Line 730-737 | ✓ Complete | Encodes `[path_len (2 bytes)][path]` |
| **Packet creation** | Line 740-747 | ✓ Complete | Creates FS_META_REQ packet |
| **Encryption** | Line 756 | ✓ Complete | Uses session AES-256-GCM |
| **Network send** | Line 757 | ✓ Complete | Sends via network engine |
| **Response handling** | Line 902 | ✗ EMPTY STUB | Needs validation |
| **Directory update** | Line 762 | ✓ Optimistic | Updates local state without waiting for response |

**Server Side Handler:** `handle_fs_meta_req()` Line 829
- Status: ✓ Fully implemented
- Decrypts path, checks if directory exists
- Returns: `[0 or 1]` (0=not-directory, 1=is-directory)

**Missing Implementation:**
```cpp
Line 902:
void ProtocolManager::handle_fs_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_META_RES" << std::endl;
}
```

---

## SECTION 3: PEERS TABLE STRUCTURE

### Current Implementation: cmd_list_peers() Line 263

**Column Configuration:**
```cpp
Line 274: std::vector<int> widths = {22, 22, 17, 22};

Columns:
1. NODE ID       (width: 22)
2. ADDRESS       (width: 22)
3. STATUS        (width: 17)
4. ENCRYPTION    (width: 22)
```

**Code for header drawing:**
```cpp
Lines 276-279:
    std::cout << "| " << std::setw(22) << "NODE ID" 
              << "| " << std::setw(22) << "ADDRESS"
              << "| " << std::setw(17) << "STATUS"
              << "| " << std::setw(22) << "ENCRYPTION" << "|\n";
```

**Code for data rows:**
```cpp
Lines 286-320:
    for (const auto& [node_id, session] : sessions) {
        std::string short_id = node_id.length() > 18 ? 
                              node_id.substr(0, 15) + "..." : node_id;
        std::string addr = session->peer_ip + ":" + std::to_string(session->peer_port);
        if (addr.length() > 20) addr = addr.substr(0, 17) + "...";
        
        // STATUS color-coded output (lines 294-312)
        // ENCRYPTION constant: "[AES-256-GCM]"
        
        std::cout << "| " << std::setw(20) << short_id
                  << "| " << std::setw(20) << addr
                  << "| " << status 
                  << "| " << encryption << "\n";
    }
```

### Issue: Missing Index Column

**To add `#` column, modify:**

1. **Line 274** - Add width for index:
   ```cpp
   std::vector<int> widths = {4, 22, 22, 17, 22};  // Add 4 for index
   ```

2. **Lines 276-279** - Add header column:
   ```cpp
   std::cout << "| " << std::setw(4) << "#"
             << "| " << std::setw(22) << "NODE ID"
             // ... rest of headers
   ```

3. **Lines 282-283** - Adjust separator:
   ```cpp
   std::cout << "|" << std::string(4, '-')  // Add for index
             << "|" << std::string(22, '-')
             // ... rest of separators
   ```

4. **Line 286** - Add counter:
   ```cpp
   int index = 1;
   for (const auto& [node_id, session] : sessions) {
       // ... existing code ...
       
       std::cout << "| " << std::setw(4) << index  // Add index output
                 << "| " << std::setw(20) << short_id
                 // ... rest of output
       index++;
   }
   ```

---

## SECTION 4: SESSION SWITCHING & ACTIVE SESSIONS

### 4.1 current_target_ State Variable

**Declaration Location:** CommandHandler.hpp line 111
```cpp
private:
    std::string current_target_;  // Current node to interact with
```

**Where SET:**

| Location | Function | Code | Purpose |
|----------|----------|------|---------|
| Line 85 | `set_current_target()` | `current_target_ = target;` | Called after `cmd_connect()` succeeds |
| Line 177 | `get_active_session()` | `current_target_ = node_id;` | Maps IP:Port to real node_id |

**Where USED in operations:**

| Command | Line | Usage |
|---------|------|-------|
| cmd_ls() | 513, 543, 547 | Get session, read target_id, send with encryption |
| cmd_get() | 574, 603, 607 | Get session, read target_id, send with encryption |
| cmd_put() | 632, 675, 679 | Get session, read target_id, send with encryption |
| cmd_cd() | 723, 752, 756 | Get session, read target_id, send with encryption |
| cmd_pwd() | 699 | Read current session directory |
| cmd_ping() | 383-402 | Parse IP:port from current_target_ |

### 4.2 Getting All Active Sessions

**Method:**
```cpp
// In SessionManager.hpp line 162
std::map<std::string, std::shared_ptr<Session>> get_all_sessions();

// In SessionManager.cpp - returns the internal map
```

**Used by:**
- `cmd_list_peers()` Line 266 - Display all sessions in table
- `send_heartbeat_pings()` Line 1488 - Send PING to all active sessions

---

## SECTION 5: NAT-RELATED LOGS & REPLAY DETECTION

### 5.1 update_peer_address() - Line 1453

**Function Purpose:** Track dynamic NAT address/port changes

**Implementation:**
```cpp
Lines 1453-1480:
bool ProtocolManager::update_peer_address(const std::string& node_id, const std::string& new_ip, uint16_t new_port) {
    auto session = session_mgr_->get_session(node_id);
    if (!session) {
        return false;
    }
    
    bool changed = false;
    
    // Check if IP changed
    if (session->peer_ip != new_ip) {
        // Suppress verbose NAT update logs to reduce console spam
        // std::cout << "[NAT-UPDATE] Peer IP changed: " << session->peer_ip << " -> " << new_ip << std::endl;  // LINE 1464
        session->peer_ip = new_ip;
        changed = true;
    }
    
    // CRITICAL: Check if port changed (Symmetric NAT behavior)
    if (session->peer_port != new_port) {
        // Suppress verbose NAT update logs to reduce console spam
        // std::cout << "[NAT-UPDATE] Peer port changed: " << session->peer_port << " -> " << new_port;  // LINE 1472
        // std::cout << " (Symmetric NAT detected!)" << std::endl;  // LINE 1473
        session->peer_port = new_port;
        session->dynamic_peer_port = new_port;  // Track dynamic port
        changed = true;
    }
    
    return changed;
}
```

**Logs emitted from update_peer_address():**
- Line 1464 (SUPPRESSED) - IP change notification
- Line 1472-1473 (SUPPRESSED) - Port change + Symmetric NAT detection

**Called from:** `dispatch_packet()` Line 54
**Which triggers:** Line 57 output `"[DISPATCH] Peer address updated (possibly Symmetric NAT)"`

### 5.2 Nonce/Replay Detection - Lines 60-66

```cpp
Lines 60-66 in dispatch_packet():
    // Check nonce first (anti-replay)
    if (!verify_nonce(hdr.sender_id, hdr.packet_nonce)) {
        // NOTE: Suppress this log - heartbeat PING packets can legitimately trigger replay detection
        // without being actual attacks due to timestamp-based nonce generation
        // std::cerr << "[PROTOCOL] Replay attack detected from " << sender_id_str << std::endl;  // LINE 64
        return;
    }
```

**Issue:** Replay detection is suppressed because PING packets with timestamp-based nonces can legitimately fail the check without being actual attacks.

**verify_nonce() Implementation - Line 192:**
```cpp
Lines 192-205:
bool ProtocolManager::verify_nonce(const uint8_t* sender_id, uint64_t nonce) {
    std::string id_str = sender_id_to_string(sender_id);
    
    // Check if we've seen this nonce before
    auto it = nonce_map_.find(id_str);
    if (it != nonce_map_.end() && it->second >= nonce) {
        return false;  // Replay detected
    }

    // Update nonce map
    nonce_map_[id_str] = nonce;

    return true;
}
```

**Behavior:**
- Keeps a map of `(sender_id -> last_nonce_seen)`
- Rejects packets if nonce <= previous nonce for same sender
- Updates map with new nonce on acceptance

