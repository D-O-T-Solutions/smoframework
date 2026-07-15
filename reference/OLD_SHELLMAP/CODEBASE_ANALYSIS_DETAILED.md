# ShellMap Codebase Analysis Report

## 1. LOG SOURCES THAT NEED SUPPRESSION

### 1.1 [DISPATCH] Logs in ProtocolManager.cpp

**Location:** `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`

#### Line 57 - NAT address update log
```cpp
Line 57:  std::cout << "[DISPATCH] Peer address updated (possibly Symmetric NAT)" << std::endl;
```
**Function:** `dispatch_packet()` (starts at line ~49-190)
**Context (5-10 lines):**
```
54:     // Update peer address (returns true if changed)
55:     bool addr_changed = update_peer_address(sender_id_str, std::string(sender_ip), sender_port);
56:     if (addr_changed && (hdr.op_code != OpCode::HELLO && hdr.op_code != OpCode::WELCOME && hdr.op_code != OpCode::AUTH)) {
57:         // Only log address changes for non-handshake packets
58:         std::cout << "[DISPATCH] Peer address updated (possibly Symmetric NAT)" << std::endl;
59:     }
```
**Suggestion:** This log appears frequently during NAT traversal. Should be suppressed or rate-limited to reduce console spam.

---

### 1.2 Heartbeat Thread PING Logs

#### Line 1512-1513 - Incomplete heartbeat warning output
```cpp
Line 1512:  std::cout << " (" << (time_since_ping / 1000000000ULL) << "s). Ping count: ";
Line 1513:  std::cout << (int)session->ping_sent_count << "/3" << std::endl;
```
**Function:** `send_heartbeat_pings()` (starts at line 1482)
**Context:**
```
1509:         // If PING has been pending for too long (45s = 3 retries), timeout the session
1510:         if (time_since_ping > PING_TIMEOUT) {
1511: //                 std::cout << "[HEARTBEAT] WARNING: No PING_ACK for " << node_id.substr(0, 8);
1512:             std::cout << " (" << (time_since_ping / 1000000000ULL) << "s). Ping count: ";
1513:             std::cout << (int)session->ping_sent_count << "/3" << std::endl;
```
**Issue:** Line 1511 is commented out, but lines 1512-1513 still output partial message without prefix. This creates orphaned logs.

#### Line 1519 - Session timeout message
```cpp
Line 1519:  std::cout << " - No response after 3 PINGs (45s)" << std::endl;
```
**Context:**
```
1515:     session->ping_sent_count++;
1516:     
1517:     if (session->ping_sent_count >= 3) {
1518: //         std::cout << "[HEARTBEAT] TIMEOUT: " << node_id.substr(0, 8);
1519:         std::cout << " - No response after 3 PINGs (45s)" << std::endl;
1520:         session_mgr_->destroy_session(node_id);
1521:         continue;
```
**Issue:** Similar orphaned log - Line 1518 commented, but 1519 still outputs.

#### Commented PING logs (should verify if needed)
```cpp
Line 535: //     std::cout << "[PROTOCOL] PING from " << sender_id_str << std::endl;
Line 558: //             std::cout << "[PROTOCOL] Pong! (" << rtt_ms << " ms)" << std::endl;
Line 581: //         std::cout << "[PROTOCOL] PING (pong) sent to " << sender_id_str << std::endl;
Line 1309: //     std::cout << "[PROTOCOL] Sending PING to " << target_ip << ":" << target_port << std::endl;
Line 1348: //      std::cout << "[PROTOCOL] PING sent to " << target_ip << ":" << target_port << " (ts=" << ping_ts << ")" << std::endl;
Line 1552: //  std::cout << "[HEARTBEAT] PING sent to " << node_id.substr(0, 8) << " ("
Line 1555: std::cerr << "[HEARTBEAT] Failed to send PING to " << node_id.substr(0, 8) << std::endl;
Line 1624: //     std::cout << "[PROTOCOL] PING_ACK sent to " << node_id.substr(0, 8) << std::endl;
```

---

### 1.3 PING-Related Logs (Active & Suppressed)

**Active PING logs:**
```cpp
Line 539:  std::cerr << "[PROTOCOL] Invalid PING payload size" << std::endl;
Line 583:  std::cerr << "[PROTOCOL] No session for PING sender: " << sender_id_str << std::endl;
Line 1344: std::cerr << "[PROTOCOL] Failed to send PING packet" << std::endl;
Line 1555: std::cerr << "[HEARTBEAT] Failed to send PING to " << node_id.substr(0, 8) << std::endl;
Line 1600: std::cerr << "[PROTOCOL] Cannot send PING_ACK: no session for " << node_id << std::endl;
Line 1620: std::cerr << "[PROTOCOL] Failed to send PING_ACK" << std::endl;
```

**CommandHandler PING output:**
```cpp
Line 409:  std::cout << COLOR_YELLOW << "[PING] Sending to " << target_ip << ":" << target_port << "..." << COLOR_RESET << std::endl;
Line 413:  std::cout << COLOR_RED << "✗ Failed to send PING" << COLOR_RESET << std::endl;
Line 419:  std::cout << COLOR_YELLOW << "[PING] Waiting for response..." << COLOR_RESET << std::endl;
```

---

## 2. FILE OPERATIONS IMPLEMENTATION STATUS

### 2.1 cmd_ls() - Line 506

**Status:** SENDS REAL SERVER API CALL
**Implementation Details:**
- **Line 520:** Builds FS_LIST_REQ packet with path
- **Line 533:** Creates FS_LIST_REQ opcode packet
- **Line 547:** Encrypts payload with session AES key
- **Line 548:** Sends packet via network engine
- **Response Handler:** `handle_fs_list_res()` at line 825 (currently empty stub)

```cpp
506: bool CommandHandler::cmd_ls(const std::vector<std::string>& args) {
     ...
520:     std::string path = args.size() > 1 ? args[1] : session->current_remote_dir;
521: 
522:     // Build payload: [path_len (2 bytes)][path]
523:     std::vector<uint8_t> payload;
524:     uint16_t path_len = path.length();
525:     payload.push_back((path_len >> 8) & 0xFF);
526:     payload.push_back(path_len & 0xFF);
527:     payload.insert(payload.end(), path.begin(), path.end());
528: 
529:     // Create and send FS_LIST_REQ packet
530:     PacketHeader hdr;
531:     hdr.op_code = static_cast<uint8_t>(OpCode::FS_LIST_REQ);
533:     ...
547:     std::vector<uint8_t> encrypted = session_mgr_->encrypt_message(current_target_, payload);
548:     net_engine_.send_packet(hdr, encrypted, session->peer_ip, session->peer_port);
```

**Server Side Handler:** `handle_fs_list_req()` at line 724
- Decrypts request
- Lists directory from `shellmap/shared/` + path
- Returns file list: `name|size|type;...` format
- Encrypts and sends FS_LIST_RES

---

### 2.2 cmd_get() - Line 562

**Status:** SENDS REAL SERVER API CALL
**Implementation Details:**
- **Line 581:** Filename parameter from args
- **Line 594:** Creates FS_DATA_REQ opcode packet
- **Line 607:** Encrypts and sends request

```cpp
562: bool CommandHandler::cmd_get(const std::vector<std::string>& args) {
     ...
580:     // Send FS_DATA_REQ packet
581:     std::string filename = args[1];
     ...
594:     hdr.op_code = static_cast<uint8_t>(OpCode::FS_DATA_REQ);
```

**Server Side Handler:** `handle_fs_data_req()` at line 906
- Decrypts filename request
- Reads file from `shellmap/shared/`
- Returns file content in FS_DATA_RES
- Security: Validates path against traversal attacks

**Response Handler:** `handle_fs_data_res()` at line 997 (currently empty stub)

---

### 2.3 cmd_put() - Line 620

**Status:** SENDS REAL SERVER API CALL
**Implementation Details:**
- **Line 642:** Checks if local file exists
- **Line 666:** Creates FS_PUT_META_REQ opcode
- **Line 679:** Encrypts and sends metadata + file size

```cpp
620: bool CommandHandler::cmd_put(const std::vector<std::string>& args) {
     ...
639:     std::string filename = args[1];
642:     // Check if file exists locally
643:     std::ifstream file(filename, std::ios::binary | std::ios::ate);
     ...
650:     // Build payload: [filename_len (2 bytes)][filename][file_size (8 bytes)]
666:     hdr.op_code = static_cast<uint8_t>(OpCode::FS_PUT_META_REQ);
```

**Server Side Handler:** `handle_fs_put_meta_req()` at line 1001
- Decrypts metadata
- Validates filename
- Returns FS_PUT_META_RES with status

**Data Handler:** `handle_fs_put_data()` at line 1077
- Receives file chunks with offset
- Writes to `shellmap/shared/` directory

**Response Handler:** `handle_fs_put_meta_res()` at line 1073 (currently empty stub)

---

### 2.4 cmd_cd() - Line 711

**Status:** SENDS REAL SERVER API CALL  
**Implementation Details:**
- **Line 730:** Path parameter from args
- **Line 743:** Creates FS_META_REQ opcode
- **Line 757:** Encrypts and sends path request

```cpp
711: bool CommandHandler::cmd_cd(const std::vector<std::string>& args) {
     ...
729:     // Send FS_META_REQ to check if directory exists
730:     std::string path = args[1];
     ...
743:     hdr.op_code = static_cast<uint8_t>(OpCode::FS_META_REQ);
757:     std::vector<uint8_t> encrypted = session_mgr_->encrypt_message(current_target_, payload);
758:     net_engine_.send_packet(hdr, encrypted, session->peer_ip, session->peer_port);
```

**Server Side Handler:** `handle_fs_meta_req()` at line 829
- Decrypts path request
- Checks if path is directory
- Returns FS_META_RES with 1-byte flag (0=file/not-exists, 1=dir)

**Response Handler:** `handle_fs_meta_res()` at line 902 (currently empty stub)

---

## 3. FILE OPERATIONS RESPONSE HANDLERS

All response handlers are currently **empty stubs** that need implementation:

| Handler | Location | Status | Issue |
|---------|----------|--------|-------|
| `handle_fs_list_res()` | Line 825 | Empty stub | Needs to parse file list and display to user |
| `handle_fs_data_res()` | Line 997 | Empty stub | Needs to receive file chunks and save to disk |
| `handle_fs_meta_res()` | Line 902 | Empty stub | Needs to validate directory exists |
| `handle_fs_put_meta_res()` | Line 1073 | Empty stub | Needs to handle server acceptance/rejection |

**Code:**
```cpp
void ProtocolManager::handle_fs_list_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_LIST_RES" << std::endl;
}

void ProtocolManager::handle_fs_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_META_RES" << std::endl;
}

void ProtocolManager::handle_fs_data_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_DATA_RES" << std::endl;
}

void ProtocolManager::handle_fs_put_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] FS_PUT_META_RES" << std::endl;
}
```

---

## 4. PEERS TABLE STRUCTURE & IMPLEMENTATION

### 4.1 Current Implementation - cmd_list_peers() at Line 263

**Current Column Structure:**
```
Line 274:  std::vector<int> widths = {22, 22, 17, 22};
Line 276-279:  4 columns: NODE ID | ADDRESS | STATUS | ENCRYPTION
```

**Detailed Code:**
```cpp
263: bool CommandHandler::cmd_list_peers(const std::vector<std::string>& args) {
264:     std::cout << "\n" << COLOR_BRIGHT_CYAN << "Active Peer Connections" << COLOR_RESET << "\n\n";
265:     
266:     auto sessions = session_mgr_->get_all_sessions();
267:     
268:     if (sessions.empty()) {
269:         std::cout << COLOR_YELLOW << "(No active sessions)" << COLOR_RESET << "\n\n";
270:         return true;
271:     }
272:     
273:     // Draw table header with proper column widths
274:     std::vector<int> widths = {22, 22, 17, 22};
275:     std::cout << std::left;
276:     std::cout << "| " << std::setw(22) << "NODE ID" 
277:               << "| " << std::setw(22) << "ADDRESS"
278:               << "| " << std::setw(17) << "STATUS"
279:               << "| " << std::setw(22) << "ENCRYPTION" << "|\n";
280:     
281:     // Separator line
282:     std::cout << "|" << std::string(22, '-') << "|" << std::string(22, '-') 
283:               << "|" << std::string(17, '-') << "|" << std::string(22, '-') << "|\n";
284:     
285:     // List sessions
286:     for (const auto& [node_id, session] : sessions) {
287:         std::string short_id = node_id.length() > 18 ? 
288:                               node_id.substr(0, 15) + "..." : node_id;
289:          ...
316:         std::cout << "| " << std::setw(20) << short_id
317:                   << "| " << std::setw(20) << addr
318:                   << "| " << status 
319:                   << "| " << encryption << "\n";
```

### 4.2 ISSUE: Missing Index Column (#)

**Current columns:** 4 (NODE ID, ADDRESS, STATUS, ENCRYPTION)
**Needed change:** Add index column at the beginning

**Suggested implementation:**
- Add `#` column at start (width: 4)
- Increment counter during loop (line 286)
- Update widths vector at line 274
- Adjust separator widths at line 282-283

---

## 5. SESSION SWITCHING MECHANISM

### 5.1 current_target_ Usage

**Declaration:** `CommandHandler.hpp` line 111
```cpp
std::string current_target_;  // Current node to interact with
```

### 5.2 Where current_target_ is SET

**Location 1: cmd_connect() - Line 85**
```cpp
84: void CommandHandler::set_current_target(const std::string& target) {
85:     current_target_ = target;
86:     is_connected_ = true;
87: }
```

**Location 2: get_active_session() - Lines 175-177**
```cpp
175:             // Found ESTABLISHED session! Update current_target_ to the real node_id
176:             std::cout << COLOR_CYAN << "[DEBUG] Mapped " << current_target_ << " -> " << node_id.substr(0, 8) << "..." << COLOR_RESET << std::endl;
177:             current_target_ = node_id;
```

### 5.3 Where current_target_ is USED

All file operations use `current_target_` to reference the active session:
- **cmd_ls():** Line 513, 543, 547
- **cmd_get():** Line 574, 603, 607
- **cmd_put():** Line 632, 675, 679
- **cmd_cd():** Line 723, 752, 756
- **cmd_pwd():** Line 699, 723
- **cmd_ping():** Line 383-402

### 5.4 Active Sessions Collection

**Method:** `SessionManager::get_all_sessions()` - SessionManager.hpp line 162
```cpp
std::map<std::string, std::shared_ptr<Session>> get_all_sessions();
```

**Used in:**
- **cmd_list_peers():** Line 266 - Iterates all sessions to display table
- **send_heartbeat_pings():** Line 1488 - Iterates all sessions to send PINGs

---

## 6. SESSION STATE MACHINE

**States (SessionManager.hpp lines 24-31):**
```cpp
enum class SessionState {
    NONE,              // No session
    INITIATED,         // Step 1: HELLO sent, waiting WELCOME
    HELLO_SENT,        // (Alias for INITIATED, tracking linear flow)
    WELCOME_RECEIVED,  // Step 2: Received WELCOME, waiting AUTH
    WELCOME_SENT,      // Step 2b: Responder sent WELCOME, waiting AUTH
    ESTABLISHED,       // Step 3: AUTH received/verified, ready to use
    CLOSED             // Session closed
};
```

**State Transitions:**
1. **NONE** → **INITIATED** (initiate_handshake() sends HELLO)
2. **INITIATED** → **WELCOME_RECEIVED** (receive WELCOME from peer)
3. **WELCOME_RECEIVED** → **ESTABLISHED** (send/receive AUTH)
4. **ESTABLISHED** → **CLOSED** (destroy_session())

**Lifecycle for responder:**
1. **NONE** → **HELLO_SENT** (echo back to initiator)
2. **HELLO_SENT** → **WELCOME_SENT** (receive HELLO, send WELCOME)
3. **WELCOME_SENT** → **ESTABLISHED** (receive AUTH, verify)

---

## 7. NAT-RELATED LOGS

### 7.1 update_peer_address() Function - Line 1453

**Purpose:** Track dynamic peer address/port changes due to Symmetric NAT

**Implementation:**
```cpp
1453: bool ProtocolManager::update_peer_address(const std::string& node_id, const std::string& new_ip, uint16_t new_port) {
1454:     auto session = session_mgr_->get_session(node_id);
1455:     if (!session) {
1456:         return false;
1457:     }
1458:     
1459:     bool changed = false;
1460:     
1461:      // Check if IP changed
1462:     if (session->peer_ip != new_ip) {
1463:         // Suppress verbose NAT update logs to reduce console spam
1464:         // std::cout << "[NAT-UPDATE] Peer IP changed: " << session->peer_ip << " -> " << new_ip << std::endl;
1465:         session->peer_ip = new_ip;
1466:         changed = true;
1467:     }
1468:     
1469:     // CRITICAL: Check if port changed (Symmetric NAT behavior)
1470:     if (session->peer_port != new_port) {
1471:         // Suppress verbose NAT update logs to reduce console spam
1472:         // std::cout << "[NAT-UPDATE] Peer port changed: " << session->peer_port << " -> " << new_port;
1473:         // std::cout << " (Symmetric NAT detected!)" << std::endl;
1474:         session->peer_port = new_port;
1475:         session->dynamic_peer_port = new_port;
1476:         changed = true;
1477:     }
1478:     
1479:     return changed;
1480: }
```

**Logs from update_peer_address():**
- **Line 1464:** (SUPPRESSED) IP change log
- **Line 1472-1473:** (SUPPRESSED) Port change log

**Called from:** dispatch_packet() line 54
**Which outputs:** Line 57 - "[DISPATCH] Peer address updated (possibly Symmetric NAT)"

### 7.2 Nonce/Replay Detection Logs - Line 60-66

```cpp
60:      // Check nonce first (anti-replay)
61:      if (!verify_nonce(hdr.sender_id, hdr.packet_nonce)) {
62:          // NOTE: Suppress this log - heartbeat PING packets can legitimately trigger replay detection
63:          // without being actual attacks due to timestamp-based nonce generation
64:          // std::cerr << "[PROTOCOL] Replay attack detected from " << sender_id_str << std::endl;
65:          return;
66:      }
```

**Issue:** The replay detection log is suppressed (line 64 commented) because PING packets with timestamp-based nonces can legitimately fail this check.

**verify_nonce() Function - Line 192:**
```cpp
192: bool ProtocolManager::verify_nonce(const uint8_t* sender_id, uint64_t nonce) {
193:     std::string id_str = sender_id_to_string(sender_id);
194:     
195:     // Check if we've seen this nonce before
196:     auto it = nonce_map_.find(id_str);
197:     if (it != nonce_map_.end() && it->second >= nonce) {
198:         return false;  // Replay detected
199:     }
200: 
201:     // Update nonce map
202:     nonce_map_[id_str] = nonce;
203: 
204:     return true;
205: }
```

---

## SUMMARY OF ISSUES & RECOMMENDATIONS

### Critical Issues:
1. **Orphaned heartbeat logs** (Lines 1512-1519) - Partial output without complete message prefix
2. **Empty response handlers** - file operations won't complete properly
3. **Missing index column** in peers table - affects usability
4. **Incomplete session switching** - No "return N" mechanism for switching between sessions

### Quick Fixes:
1. **Suppress/fix heartbeat logs** - Remove lines 1512-1513, 1519 OR complete the commented lines 1511, 1518
2. **Implement response handlers** - Parse FS_LIST_RES, FS_DATA_RES, FS_META_RES responses
3. **Add # column to peers table** - Include session index for quick switching
4. **Implement session switching** - Allow `return N` to switch to session number N

### Log Suppression Targets:
- Line 57: [DISPATCH] log (too frequent during normal NAT operations)
- Lines 1512-1513, 1519: Orphaned heartbeat logs
- Lines 1464, 1472-1473: NAT update logs (already suppressed as comments)

