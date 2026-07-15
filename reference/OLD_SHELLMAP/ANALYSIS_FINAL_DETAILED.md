# PHÂN TÍCH CODEBASE SHELLMAP - BÁO CÁO CHI TIẾT

## 1. TẤT CẢ VỊ TRÍ IN PROMPT

### CommandHandler.cpp - print_prompt()
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/CommandHandler.cpp`

#### Vị trí 1: Định nghĩa hàm print_prompt()
- **Line 135-145**: Hàm `void CommandHandler::print_prompt()`
```cpp
135: void CommandHandler::print_prompt() {
136:     std::cout << COLOR_BRIGHT_CYAN;
137:     if (current_target_.empty()) {
138:         std::cout << "[ShellMap] ❯ " << COLOR_RESET;
139:     } else {
140:         // Shorten the target ID to first 8 chars
141:         std::string short_id = current_target_.substr(0, 8);
142:         std::cout << "[ShellMap] @ " << short_id << " ❯ " << COLOR_RESET;
143:     }
144:     std::fflush(stdout);
145: }
```

#### Vị trí 2-5: Gọi print_prompt() từ main.cpp
- **File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/main.cpp`

| Line | Function | Context |
|------|----------|---------|
| 59 | `main()` | Khởi động CLI |
| 68 | `main()` | Sau khi parse command |
| 124 | `main()` | Ngoài vòng lặp |
| 150 | `main()` | Trong xử lý ERROR |
| 164 | `main()` | Phục hồi sau lỗi |

#### Vị trí 6-7: Gọi print_prompt() từ main2.cpp
- **File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/main2.cpp`
- **Line 70**: Định nghĩa hàm `void print_prompt()` riêng biệt (CẢNH BÁO: Duplicate!)
- **Calls**: Lines 690, 995, 1310, 1407, 1434

---

## 2. LOG [HANDSHAKE-FINAL] VẪN TỒN TẠI

### FOUND: Log còn sót tại ProtocolManager.cpp
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`

#### Line 482 - ACTIVE LOG IN handle_auth()
```cpp
480: void ProtocolManager::handle_auth(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
481:     std::string peer_id_str = sender_id_to_string(hdr.sender_id);
482:     std::cout << "\n[HANDSHAKE-FINAL] Received AUTH from " << peer_id_str.substr(0, 8) << "..." << std::endl;
483:     
484:     auto session = session_mgr_->get_session(peer_id_str);
...
```

**Status**: LIVE (không có comment)
**Function**: `void ProtocolManager::handle_auth()`
**Issue**: Đây là log ACTIVE duy nhất cho handshake final

#### Các log KHÁC bị comment:
- Line 497: `// std::cout << "[HANDSHAKE-FINAL] Extracted initiator Kyber SS..."`
- Line 516: `// std::cout << "[HANDSHAKE-FINAL] Keys established successfully"`
- Line 522: `// std::cout << "[HANDSHAKE-FINAL] === SESSION ESTABLISHED ==="`

---

## 3. FILE OPERATION REQUEST/RESPONSE FLOW

### handle_fs_list_req() - CHỈ XỬ LÝ LIST REQUEST
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`
**Lines**: 724-813

#### Công việc hiện tại:
```cpp
724: void ProtocolManager::handle_fs_list_req(...) {
    // 1. Xác minh session từ sender
    // 2. Giải mã payload
    // 3. Phân tích path từ plaintext
    // 4. Kiểm tra security (path traversal protection)
    // 5. Duyệt thư mục thực tế: "shellmap/shared/" + path
    // 6. Xây dựng FS_LIST_RES packet
    // 7. Gửi response
```

#### Key implementation:
- **Line 768**: Build path: `std::string full_path = "shellmap/shared/" + (path.empty() ? "" : path);`
- **Line 773-798**: Duyệt thư mục thực tế (KHÔNG GIẢ LẬP)
- **Line 806-813**: Tạo FS_LIST_RES packet

**Status**: FUNCTIONAL (thực hiện listing thực tế)

### cmd_ls() - CÓ PLACEHOLDER MESSAGES
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/CommandHandler.cpp`
**Lines**: 512-561

#### Công việc hiện tại:
```cpp
512: bool CommandHandler::cmd_ls(const std::vector<std::string>& args) {
    // 1. Xác minh session
    // 2. Xây dựng FS_LIST_REQ payload
    // 3. Gửi encrypted packet
    // 4. ===== PLACEHOLDER MESSAGES =====
556:    std::cout << COLOR_YELLOW << "[LS] Listing directory..." << COLOR_RESET << std::endl;
559:    std::cout << COLOR_CYAN << "." << COLOR_RESET << std::endl;
560:    std::cout << COLOR_CYAN << ".." << COLOR_RESET << std::endl;
561:    return true;
```

#### ISSUE DETECTED:
- **Line 559-560**: In giả lập `.` và `..` (HARDCODED!)
- **Line 557**: Comment rõ: `// In a real implementation, we would wait for FS_LIST_RES...`
- **Vấn đề**: cmd_ls() gửi request nhưng KHÔNG đợi response, chỉ in placeholder

**Status**: INCOMPLETE (không xử lý response từ peer)

---

## 4. ROUTING TABLE UPDATE FLOW

### handle_welcome() - CÓ GỌIERTING TABLE UPDATE
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`
**Lines**: 351-476

#### Key finding:
```cpp
472: session->state = SessionManager::SessionState::ESTABLISHED;
473: // HOTFIX: Register peer in routing table when session becomes ESTABLISHED
474: route_table_.update_route(peer_id_str, session->peer_ip, session->peer_port);
475: // std::cout << "[HANDSHAKE-3] === SESSION ESTABLISHED ===" << std::endl;
```

**Status**: CÓ update routing table (Line 474)

### handle_auth() - CÓ GỌIERTING TABLE UPDATE
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/ProtocolManager.cpp`
**Lines**: 480-523

#### Key finding:
```cpp
519: session->state = SessionManager::SessionState::ESTABLISHED;
520: // HOTFIX: Register peer in routing table when session becomes ESTABLISHED
521: route_table_.update_route(peer_id_str, session->peer_ip, session->peer_port);
522: // std::cout << "[HANDSHAKE-FINAL] === SESSION ESTABLISHED ===" << std::endl;
```

**Status**: CÓ update routing table (Line 521)

### cmd_list_nodes() - LẶP QUA SessionManager, KHÔNG PHẢI RoutingTable
**File**: `/home/nguyenduccanh/shellmap_project/hello/ShellMap/src/CommandHandler.cpp`
**Lines**: 334-360

#### CRITICAL FINDING:
```cpp
334: bool CommandHandler::cmd_list_nodes(const std::vector<std::string>& args) {
335:     std::cout << "\n" << COLOR_BRIGHT_CYAN << "Known Nodes in Routing Table" << COLOR_RESET << "\n\n";
336:     
337:     // Get all nodes from routing table
338:     // Note: We need to add a get_all_nodes() method to RoutingTable if it doesn't exist
339:     // For now, we'll display a placeholder with proper formatting
340:     
341:     // Draw table header...
    
353:     // TODO: Iterate through route_table to get real nodes
354:     // For now showing placeholder
```

**Status**: 
- ❌ KHÔNG lặp qua RoutingTable
- ❌ KHÔNG lặp qua SessionManager
- ⚠️ CHỈ in table header và footer trống

#### So sánh với cmd_peers():
```cpp
168: auto all_sessions = session_mgr_->get_all_sessions();
169: for (const auto& [node_id, sess] : all_sessions) {
    // Lặp qua SessionManager (CORRECT)
```

**Issue**: cmd_list_nodes() nên lặp qua `route_table_` nhưng hiện đang để trống (TODO)

---

## TÓMALẤU KIẾN

### 1. Print Prompt
✅ Tìm được 7 vị trí gọi print_prompt()
- CommandHandler::print_prompt() định nghĩa tại Line 135
- main.cpp gọi 5 lần
- main2.cpp có duplicate definition và gọi 6 lần

### 2. [HANDSHAKE-FINAL] Log
✅ Tìm được 1 log ACTIVE tại Line 482 (handle_auth())
⚠️ 3 log khác bị comment (Lines 497, 516, 522)

### 3. File Operations
✅ handle_fs_list_req() làm việc: thực hiện directory listing thực tế
⚠️ cmd_ls() có vấn đề: in placeholder "." và ".." thay vì in kết quả từ response

### 4. Routing Table Updates
✅ handle_welcome() Line 474: Gọi route_table_.update_route()
✅ handle_auth() Line 521: Gọi route_table_.update_route()
❌ cmd_list_nodes() KHÔNG lặp qua routing table (chỉ in placeholder)

