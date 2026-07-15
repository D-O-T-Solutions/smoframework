# SHELLMAP CODEBASE ANALYSIS - FINAL SUMMARY REPORT

**Date**: April 16, 2026  
**Analyzed**: ShellMap Project  
**Files Scanned**: 8 source files (.cpp) + headers

---

## EXECUTIVE SUMMARY

Found **4 critical issues** and **7 active code locations** that need attention:

### Issues Found:
1. ✅ **7 Prompt printing locations** - All identified
2. ⚠️ **1 [HANDSHAKE-FINAL] log** - Still active at line 482
3. ❌ **cmd_ls() placeholder** - Shows fake "." and ".." instead of real files
4. ❌ **cmd_list_nodes() incomplete** - Shows empty table (TODO not implemented)

### Routing Table:
✅ Both `handle_welcome()` (line 474) and `handle_auth()` (line 521) call `route_table_.update_route()`

---

## SECTION 1: PROMPT PRINTING LOCATIONS

### Primary Definition
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/CommandHandler.cpp`  
**Lines**: 135-145  
**Function**: `void CommandHandler::print_prompt()`

```cpp
void CommandHandler::print_prompt() {
    std::cout << COLOR_BRIGHT_CYAN;
    if (current_target_.empty()) {
        std::cout << "[ShellMap] ❯ " << COLOR_RESET;
    } else {
        std::string short_id = current_target_.substr(0, 8);
        std::cout << "[ShellMap] @ " << short_id << " ❯ " << COLOR_RESET;
    }
    std::fflush(stdout);
}
```

### All Calls

| # | Line | File | Context | Status |
|---|------|------|---------|--------|
| 1 | 59 | main.cpp | Initial CLI prompt | Active |
| 2 | 68 | main.cpp | After command success | Active |
| 3 | 124 | main.cpp | Connection failed | Active |
| 4 | 150 | main.cpp | Error handling | Active |
| 5 | 164 | main.cpp | Resume after exception | Active |
| 6 | 70 | main2.cpp | **DUPLICATE DEFINITION** | ⚠️ |
| 7-11 | 690,995,1310,1407,1434 | main2.cpp | Multiple calls in separate function | Active |

### Warnings
- **main2.cpp line 70**: Contains standalone `void print_prompt()` function (NOT a class method)
- This is a DUPLICATE and may conflict with CommandHandler::print_prompt()
- Recommendation: Use only CommandHandler version or consolidate

---

## SECTION 2: [HANDSHAKE-FINAL] LOG STILL PRESENT

### Active Log - NEEDS REMOVAL

**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`  
**Line**: 482  
**Function**: `void ProtocolManager::handle_auth()`

```cpp
480: void ProtocolManager::handle_auth(...) {
481:     std::string peer_id_str = sender_id_to_string(hdr.sender_id);
482:     std::cout << "\n[HANDSHAKE-FINAL] Received AUTH from " << peer_id_str.substr(0, 8) << "..." << std::endl;
483:     // ... rest of function
```

**Status**: 🔴 **ACTIVE** - NOT COMMENTED  
**Action**: Comment this line to clean up handshake logs

### Other Handshake Logs (Already Commented)

```cpp
// Line 497:
// std::cout << "[HANDSHAKE-FINAL] Extracted initiator Kyber SS from AUTH: " 
//           << bytes_to_hex_short(initiator_kyber_ss) << "..." << std::endl;

// Line 516:
// std::cout << "[HANDSHAKE-FINAL] Keys established successfully" << std::endl;

// Line 522:
// std::cout << "[HANDSHAKE-FINAL] === SESSION ESTABLISHED ===" << std::endl;
```

---

## SECTION 3: FILE OPERATION REQUEST/RESPONSE

### Server Side: handle_fs_list_req()
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`  
**Lines**: 724-823  
**Status**: ✅ **WORKING CORRECTLY**

What it does:
1. Receives FS_LIST_REQ from remote client
2. Decrypts payload using AES-256-GCM
3. Parses requested path
4. **PERFORMS REAL DIRECTORY LISTING** on `shellmap/shared/<path>`
5. Builds FS_LIST_RES response
6. Sends encrypted response back

Key line:
```cpp
768: std::string full_path = "shellmap/shared/" + (path.empty() ? "" : path);
// ... then actual fs::directory_iterator loop follows
```

### Client Side: cmd_ls()
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/CommandHandler.cpp`  
**Lines**: 512-561  
**Status**: ❌ **BROKEN - INCOMPLETE IMPLEMENTATION**

What it currently does:
1. Sends FS_LIST_REQ to server ✅
2. **Then immediately prints fake "." and ".."** ❌
3. Does NOT wait for response ❌
4. Does NOT parse response ❌

Problematic code:
```cpp
556: std::cout << COLOR_YELLOW << "[LS] Listing directory..." << COLOR_RESET << std::endl;
557: // In a real implementation, we would wait for FS_LIST_RES and parse the response
558: std::cout << COLOR_CYAN << "." << COLOR_RESET << std::endl;
559: std::cout << COLOR_CYAN << ".." << COLOR_RESET << std::endl;
560: return true;
```

**Issue Severity**: HIGH  
**Fix Needed**: 
- Add async listener for FS_LIST_RES packet
- Parse response containing real file list
- Display actual files instead of hardcoded "." and ".."

---

## SECTION 4: ROUTING TABLE UPDATES

### 1. handle_welcome() - Updates Routing Table ✅

**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`  
**Lines**: 351-476

```cpp
472: session->state = SessionManager::SessionState::ESTABLISHED;
473: // HOTFIX: Register peer in routing table when session becomes ESTABLISHED
474: route_table_.update_route(peer_id_str, session->peer_ip, session->peer_port);
475: // std::cout << "[HANDSHAKE-3] === SESSION ESTABLISHED ===" << std::endl;
```

**Status**: ✅ YES - Route table updated at line 474

### 2. handle_auth() - Updates Routing Table ✅

**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`  
**Lines**: 480-523

```cpp
519: session->state = SessionManager::SessionState::ESTABLISHED;
520: // HOTFIX: Register peer in routing table when session becomes ESTABLISHED
521: route_table_.update_route(peer_id_str, session->peer_ip, session->peer_port);
522: // std::cout << "[HANDSHAKE-FINAL] === SESSION ESTABLISHED ===" << std::endl;
```

**Status**: ✅ YES - Route table updated at line 521

### 3. cmd_list_nodes() - DOES NOT USE ROUTING TABLE ❌

**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/CommandHandler.cpp`  
**Lines**: 334-360

```cpp
334: bool CommandHandler::cmd_list_nodes(...) {
335:     std::cout << "\n" << COLOR_BRIGHT_CYAN << "Known Nodes in Routing Table" << COLOR_RESET << "\n\n";
336:     
337:     // Get all nodes from routing table
338:     // Note: We need to add a get_all_nodes() method to RoutingTable if it doesn't exist
339:     // For now, we'll display a placeholder with proper formatting
340:     
341:     // Draw table header...
353:     // TODO: Iterate through route_table to get real nodes
354:     // For now showing placeholder
355:     
356:     // Draw empty separator
357:     std::cout << COLOR_YELLOW << "(To see nodes, connect to a peer network or bootstrap from SuperNode)" << COLOR_RESET << "\n\n";
358:     return true;
359: }
```

**Status**: ❌ NO - Does NOT iterate over routing table

**Issues**:
- Title says "Known Nodes in Routing Table" but shows nothing
- Line 353: TODO comment explicitly says "Iterate through route_table"
- No iteration code present
- Shows only empty table placeholder

**What it should do**:
- Either iterate over `route_table_` member variable
- OR iterate over SessionManager sessions (like cmd_peers() does)
- Display actual node information

---

## DETAILED FINDINGS TABLE

| Issue | Line(s) | File | Status | Priority | Action |
|-------|---------|------|--------|----------|--------|
| print_prompt() definition | 135-145 | CommandHandler.cpp | LIVE | LOW | No change needed |
| print_prompt() calls | 59,68,124,150,164 | main.cpp | LIVE | LOW | No change needed |
| print_prompt() duplicate | 70,690,995,1310,1407,1434 | main2.cpp | LIVE | MEDIUM | Remove or consolidate |
| [HANDSHAKE-FINAL] log | 482 | ProtocolManager.cpp | ACTIVE | MEDIUM | Comment out |
| handle_fs_list_req() | 724-823 | ProtocolManager.cpp | WORKING | LOW | No change |
| cmd_ls() placeholders | 559-560 | CommandHandler.cpp | BROKEN | HIGH | Implement response handling |
| handle_welcome() routing | 474 | ProtocolManager.cpp | WORKING | LOW | No change |
| handle_auth() routing | 521 | ProtocolManager.cpp | WORKING | LOW | No change |
| cmd_list_nodes() iteration | 353-354 | CommandHandler.cpp | BROKEN | HIGH | Implement iteration |

---

## CODE LOCATIONS REFERENCE

### Absolute File Paths

```
/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/CommandHandler.cpp
  - Line 135-145: print_prompt() definition
  - Line 334-360: cmd_list_nodes() empty implementation
  - Line 512-561: cmd_ls() with placeholders

/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp
  - Line 351-476: handle_welcome() with routing update
  - Line 480-523: handle_auth() with routing update and active log
  - Line 724-823: handle_fs_list_req() working implementation

/home/nguyenduccanh/shellmap_project/hello/ShellMap/main.cpp
  - Line 59, 68, 124, 150, 164: print_prompt() calls

/home/nguyenduccanh/shellmap_project/hello/ShellMap/main2.cpp
  - Line 70: Duplicate print_prompt() definition
  - Line 690, 995, 1310, 1407, 1434: print_prompt() calls
```

---

## RECOMMENDATIONS

### Immediate Actions (Priority: HIGH)
1. **Comment line 482** in ProtocolManager.cpp - Remove [HANDSHAKE-FINAL] log
2. **Implement cmd_ls() response handler** - Replace hardcoded "." and ".."
3. **Implement cmd_list_nodes() iteration** - Display actual routing table nodes

### Code Cleanup (Priority: MEDIUM)
1. Consolidate print_prompt() definition - Use only CommandHandler version
2. Remove duplicate function from main2.cpp

### Testing
- Verify file listing works end-to-end (request → response → display)
- Verify "nodes" command shows all connected peers
- Verify routing table persists across sessions

---

## ANALYSIS METADATA

- **Total Issues Found**: 4
- **Active Locations**: 7
- **Status**: Complete scan of src/*.cpp files
- **Coverage**: ProtocolManager, CommandHandler, main entry points
- **Recommendations**: 3 high-priority, 2 medium-priority fixes

