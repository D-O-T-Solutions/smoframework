# ShellMap Codebase Analysis Report

## 1. SESSION LOOKUP ISSUE

### Current Format of `current_target_`
- **Format**: `IP:Port` (string format)
- **Example**: "192.168.1.100:5555"
- **Location**: CommandHandler.hpp, line 111: `std::string current_target_;`
- **Set in**: CommandHandler.cpp, line 185: `set_current_target(target_ip + ":" + std::to_string(target_port));`

**CRITICAL ISSUE**: `current_target_` is stored as **IP:Port string**, but `get_session()` expects a **node_id** (64-char hex string). This causes the following mismatches:

```cpp
// Line 454 in CommandHandler.cpp - WRONG: tries to use IP:Port as node_id
auto session = session_mgr_->get_session(current_target_);

// Line 482 in CommandHandler.cpp - WRONG: tries to copy IP:Port into 32-byte node_id
std::copy(current_target_.begin(), current_target_.begin() + 32, hdr.target_id);
```

### How `get_session()` is Called

**In CommandHandler.cpp:**
- Line 212: `auto sessions = session_mgr_->get_all_sessions();` (peers command)
- Line 436: `auto sessions = session_mgr_->get_all_sessions();` (me command)
- Line 454: `auto session = session_mgr_->get_session(current_target_);` (ls command)
- Line 508: `auto session = session_mgr_->get_session(current_target_);` (get command)
- Line 560: `auto session = session_mgr_->get_session(current_target_);` (put command)
- Line 621: `auto session = session_mgr_->get_session(current_target_);` (pwd command)
- Line 640: `auto session = session_mgr_->get_session(current_target_);` (cd command)

**In ProtocolManager.cpp:**
- Line 359: `auto session = session_mgr_->get_session(peer_id_str);` (during WELCOME handling)
- Line 368: `session = session_mgr_->get_session(peer_id_str);` (after migration)
- Multiple other locations with 64-char hex string node IDs

### `get_all_sessions()` Function

**Location**: SessionManager.hpp, line 162; SessionManager.cpp, line 247
```cpp
std::map<std::string, std::shared_ptr<Session>> get_all_sessions() {
    return sessions_;
}
```

**Status**: ✓ EXISTS and is used correctly
- Returns entire sessions_ map with node_id keys (64-char hex strings)

### RoutingTable IP:Port Lookup

**Location**: RoutingTable.hpp, lines 145-160

**Available Methods**:
```cpp
bool get_route(string id, string& out_ip, int& out_port, bool& out_is_direct);
bool get_route(string id, string& out_ip, int& out_port);
```

**Status**: ✓ SUPPORTS lookup by node_id only
- **NO** IP:Port reverse lookup capability
- Takes node_id, returns IP:Port
- No function to find node_id by IP:Port

---

## 2. NODES COMMAND ISSUE

### `cmd_list_nodes()` Implementation

**Location**: CommandHandler.cpp, lines 274-300

**Current Implementation**:
```cpp
bool CommandHandler::cmd_list_nodes(const std::vector<std::string>& args) {
    std::cout << "\n" << COLOR_BRIGHT_CYAN << "Known Nodes in Routing Table" << COLOR_RESET << "\n\n";
    
    // Draw table header with proper column widths
    std::vector<int> widths = {20, 25, 15, 20};
    std::cout << std::left;
    std::cout << "| " << std::setw(20) << "NODE ID" 
              << "| " << std::setw(25) << "ADDRESS"
              << "| " << std::setw(15) << "TYPE"
              << "| " << std::setw(20) << "LAST SEEN" << "|\n";
    
    // Separator line
    std::cout << "|" << std::string(22, '-') << "|" << std::string(27, '-') 
              << "|" << std::string(17, '-') << "|" << std::string(22, '-') << "|\n";
    
    // TODO: Iterate through route_table to get real nodes
    // For now showing placeholder
    
    std::cout << "|" << std::string(22, '-') << "|" << std::string(27, '-') 
              << "|" << std::string(17, '-') << "|" << std::string(22, '-') << "|\n";
    std::cout << COLOR_YELLOW << "(To see nodes, connect to a peer network or bootstrap from SuperNode)" << COLOR_RESET << "\n\n";
    return true;
}
```

**Status**: ⚠️ INCOMPLETE - Shows header/footer but no actual data from routing table

### `routing_table_->add_node()` Signature

**Status**: ✗ DOES NOT EXIST

**Available RoutingTable Methods** (RoutingTable.hpp):
- `void update_route(string id, string ip, int port, bool is_relayed = false)` (line 122)
- `bool get_route(string id, string& out_ip, int& out_port, bool& out_is_direct)` (line 145)
- `vector<SuperNodeInfo> get_all_supernodes()` (line 232)
- `bool is_supernode(string id)` (line 209)
- `bool check_my_role(string my_id)` (line 217)
- `void clean_temporary_nodes()` (line 242)
- `bool get_bootstrap(string& out_ip, int& out_port)` (line 162)

**No public method to iterate all nodes** - Would need to add to RoutingTable

### When/Where `add_node` is Called

**Status**: N/A - Function doesn't exist. Used instead:
- **`update_route()`** called when receiving IAM/discovery responses
- **`load_db()`** (line 85) loads nodes from JSON files on startup

---

## 3. HANDSHAKE COMPLETION

### Session State Transition to ESTABLISHED

**Two Locations Where State Becomes ESTABLISHED**:

#### Location 1: In `handle_welcome()` (ProtocolManager.cpp, line 470)
```cpp
// Line 470 in handle_welcome():
session->state = SessionManager::SessionState::ESTABLISHED;
// std::cout << "[HANDSHAKE-3] === SESSION ESTABLISHED ===" << std::endl;
```

#### Location 2: In `handle_auth()` (ProtocolManager.cpp, line 515)
```cpp
// Line 515 in handle_auth():
session->state = SessionManager::SessionState::ESTABLISHED;
// std::cout << "[HANDSHAKE-FINAL] === SESSION ESTABLISHED ===" << std::endl;
```

**Actual Transitions**:
- **handle_welcome()** (ACTIVE): Line 470 - Sets ESTABLISHED when initiator completes WELCOME
- **handle_auth()** (ACTIVE): Line 515 - Sets ESTABLISHED when responder completes AUTH

### All [HANDSHAKE] and [SESSION] Log Statements

**Active Visible Statements** (NOT commented):
1. **ProtocolManager.cpp:240** - `cout << "\n[HANDSHAKE-2] === RESPOND: Received HELLO..."`
2. **ProtocolManager.cpp:351** - `cout << "\n[HANDSHAKE-3] === FINALIZE: Received WELCOME..."`
3. **ProtocolManager.cpp:478** - `cout << "\n[HANDSHAKE-FINAL] Received AUTH..."`
4. **ProtocolManager.cpp:57** - `cout << "[DISPATCH] Peer address updated..."`
5. **SessionManager.cpp:89** - `cerr << "[SESSION] DEBUG: establish_session called..."`
6. **SessionManager.cpp:92** - `cerr << "[SESSION] Session not found!"`
7. **SessionManager.cpp:98** - `cerr << "[SESSION] Missing handshake state..."`
8. **SessionManager.cpp:114** - `cerr << "[SESSION] Failed to compute X25519..."`
9. **SessionManager.cpp:139-141** - Debug output during establish_session (lines 139-141, printed with `cout <<`)

**Commented Statements** (with //):
- Lines 258, 283, 288, 297, 305, 339, 342, 342, 363, 366, 388, 392, 402, 406, 418, 426, 435, 446, 468, 471, 493, 512, 516, 1296, 1261, 1281
- SessionManager.cpp: Lines 152, 266, 278, 319, 328, 335, 346-350, 356-357, 361, 366, 368, 387

### AES Keys Being Printed to stdout

**Location 1**: SessionManager.cpp, line 146
```cpp
std::cout << "  AES Key: " << bytes_to_hex_short_vec(session->aes_key) 
          << "... (len=" << session->aes_key.size() << ")" << std::endl;
```

**Location 2**: SessionManager.cpp, line 147
```cpp
std::cout << "  AES IV:  " << bytes_to_hex_short_vec(session->aes_iv) 
          << " (len=" << session->aes_iv.size() << ")" << std::endl;
```

**Location 3**: SessionManager.cpp, line 219
```cpp
std::cout << "  AES Key: " << bytes_to_hex_short(std::string((char*)session->aes_key.data(), session->aes_key.size())) 
          << "... (len=" << session->aes_key.size() << ")" << std::endl;
```

**Additionally printed**:
- SessionManager.cpp:111-112 - Prints ECDH private key and peer public key
- SessionManager.cpp:139-141 - Prints Kyber SS values and ECDH SS
- SessionManager.cpp:169-170 - Prints send counter, nonce, and key during encryption
- SessionManager.cpp:217-220 - Prints recv counter, nonce, key, and ciphertext details during decryption

---

## 4. CURRENT BYE/QUIT LOGIC

### Bye/Quit Commands Status

**Status**: ✗ DO NOT EXIST

**Current Commands**:
- `exit` (CommandHandler.cpp:149) - Exits entire program
- `disconnect` - Not implemented
- `bye` - Not implemented  
- `quit` - Not implemented

**Exit Implementation** (CommandHandler.cpp, lines 802-805):
```cpp
bool CommandHandler::cmd_exit(const std::vector<std::string>& args) {
    std::cout << COLOR_CYAN << "Exiting ShellMap..." << COLOR_RESET << std::endl;
    return true;
}
```

### How `cmd_connect()` Sets `current_target_`

**Location**: CommandHandler.cpp, lines 149-191

**Full Implementation**:
```cpp
bool CommandHandler::cmd_connect(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << COLOR_YELLOW << "Usage: connect <node_id|ip:port>" << COLOR_RESET << std::endl;
        return false;
    }
    
    std::string target = args[1];
    
    // Parse ip:port or node_id
    size_t colon_pos = target.find(':');
    std::string target_ip;
    int target_port = 5555;  // Default port
    
    if (colon_pos != std::string::npos) {
        // Format: ip:port
        target_ip = target.substr(0, colon_pos);
        try {
            target_port = std::stoi(target.substr(colon_pos + 1));
        } catch (...) {
            std::cout << COLOR_RED << "✗ Invalid port number" << COLOR_RESET << std::endl;
            return false;
        }
    } else {
        // Assume it's an IP address without port
        target_ip = target;
    }
    
    // Initiate handshake via ProtocolManager
    std::cout << COLOR_YELLOW << "[CONNECT] Initiating handshake with " << target_ip << ":" << target_port << "..." << COLOR_RESET << std::endl;
    
    if (!proto_mgr_->initiate_handshake(target_ip, target_port)) {
        std::cout << COLOR_RED << "✗ Failed to send HELLO packet" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Set target and mark as connecting (NOT connected yet - handshake pending)
    set_current_target(target_ip + ":" + std::to_string(target_port));  // <-- SETS current_target_ to IP:Port
    std::cout << COLOR_GREEN << "[CONNECT] ✓ HELLO sent! Waiting for WELCOME from peer..." << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "[CONNECT] Handshake in progress (async). Monitor with 'peers' command." << COLOR_RESET << std::endl;
    
    return true;
}
```

**Key Points**:
- Accepts both `node_id` and `ip:port` format from user
- Only handles IP:Port internally
- Sets `current_target_` = `IP:Port` string (line 185)
- Does NOT store actual peer node_id from handshake response

---

## KEY FUNCTION SIGNATURES

### SessionManager Functions

| Function | Location | Signature |
|----------|----------|-----------|
| `get_session()` | SessionManager.cpp:47 | `std::shared_ptr<Session> get_session(const std::string& node_id)` |
| `get_all_sessions()` | SessionManager.cpp:247 | `std::map<std::string, std::shared_ptr<Session>> get_all_sessions()` |
| `establish_session()` | SessionManager.cpp:88 | `bool establish_session(const std::string& node_id)` |
| `migrate_session()` | SessionManager.cpp:318 | `bool migrate_session(const std::string& placeholder_id, const std::string& real_id)` |
| `find_placeholder_session()` | SessionManager.cpp:372 | `std::pair<std::string, std::shared_ptr<Session>> find_placeholder_session()` |

### ProtocolManager Functions

| Function | Location | Signature |
|----------|----------|-----------|
| `initiate_handshake()` | ProtocolManager.cpp:1235 | `bool initiate_handshake(const std::string& target_ip, int target_port)` |
| `send_ping()` | ProtocolManager.cpp:1302 | `bool send_ping(const std::string& target_ip, int target_port)` |
| `send_message()` | ProtocolManager.cpp:1346 | `bool send_message(const std::string& node_id, const std::string& message)` |
| `send_ping_ack()` | ProtocolManager.cpp:1589 | `void send_ping_ack(const std::string& node_id)` |
| `send_heartbeat_pings()` | ProtocolManager.cpp:1474 | `int send_heartbeat_pings()` |

### RoutingTable Methods

| Function | Location | Signature |
|----------|----------|-----------|
| `update_route()` | RoutingTable.hpp:122 | `void update_route(string id, string ip, int port, bool is_relayed = false)` |
| `get_route()` | RoutingTable.hpp:145 | `bool get_route(string id, string& out_ip, int& out_port, bool& out_is_direct)` |
| `get_all_supernodes()` | RoutingTable.hpp:232 | `vector<SuperNodeInfo> get_all_supernodes()` |

---

## SUMMARY OF ISSUES

### 1. Critical: current_target_ Format Mismatch
- **Problem**: Stored as IP:Port but used where node_id (64-hex) expected
- **Affected**: All file operations (ls, get, put, cd, pwd)
- **Impact**: Commands fail because node_id lookup returns nullptr

### 2. Session Lookup Impossible
- **Problem**: No way to find session by IP:Port
- **Impact**: File commands using current_target_ as IP:Port cannot find session

### 3. Nodes Command Incomplete
- **Problem**: No method to iterate all nodes from RoutingTable
- **Impact**: "nodes" command shows header but no data

### 4. AES Keys Exposed
- **Problem**: Lines 146-147, 219 in SessionManager.cpp print full AES keys to stdout
- **Impact**: Security risk - keys visible in terminal logs

### 5. Handshake Debug Output
- **Problem**: Lines 240, 351, 478 in ProtocolManager.cpp print handshake progress
- **Impact**: Terminal cluttered with progress messages

### 6. No Disconnect Command
- **Problem**: Users cannot explicitly disconnect
- **Impact**: Sessions remain active until timeout

---

## REQUIRED FIXES

1. **Change current_target_ to node_id format** (64-hex string)
   - Update cmd_connect() to track node_id after handshake
   - Update all file commands to use node_id

2. **Add IP:Port to node_id reverse lookup in RoutingTable**
   - Add `bool find_node_by_address(ip, port, out_node_id)`

3. **Implement nodes command**
   - Add getter method to RoutingTable
   - Iterate and display all known nodes

4. **Remove AES key printing**
   - Delete lines 146-147, 219 in SessionManager.cpp
   - Remove intermediate key printing (lines 111-112, 139-141, 169-170, 217-220)

5. **Comment out handshake debug output**
   - Lines 240, 351, 478 in ProtocolManager.cpp

6. **Add disconnect/bye commands**
   - Destroy session and clear current_target_
