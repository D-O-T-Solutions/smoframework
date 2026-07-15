#ifndef ROUTING_TABLE_HPP
#define ROUTING_TABLE_HPP

#include <iostream>
#include <map>
#include <string>
#include <ctime>
#include <vector>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include "json.hpp" // Dùng luôn thư viện JSON xịn xò

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std;

struct NodeRoute {
    string node_id;
    string ip;
    int port;
    bool is_direct;      
    time_t last_seen;
    bool is_supernode;
    bool is_relayed; // <--- THÊM CỜ NÀY    
};

struct SuperNodeInfo {
    string id;
    string ip;
    int port;
};

class RoutingTable {
private:
    map<string, NodeRoute> table;
    
    // Đường dẫn "Chuẩn" (Nơi lưu trữ chính thức)
    const string INTERNAL_DB_PATH = "shellmap/nodes.json";
    
    // Đường dẫn "Mồi" (File tải về để ngay cạnh file exe)
    const string EXTERNAL_DB_PATH = "nodes.json";

    // Hàm lưu danh bạ (Luôn lưu vào chỗ chuẩn)
    void save_db() {
        if (!fs::exists("shellmap")) fs::create_directories("shellmap");

        json j_root;
        j_root["updated_at"] = time(0);
        j_root["nodes"] = json::array();

        for (const auto& pair : table) {
            const NodeRoute& r = pair.second;
            
            if (r.is_supernode) {
                // Cho qua, không làm gì cả để nó chạy xuống đoạn push_back bên dưới
            }
            // 2. Nếu KHÔNG PHẢI SuperNode -> Mới áp dụng luật lọc khắt khe
            else {
                // Nếu không phải Direct hoặc là Relay -> Bỏ qua (Không lưu rác)
                if (!r.is_direct || r.is_relayed) continue;
            }

            json j_node;
            j_node["id"] = r.node_id;
            j_node["ip"] = r.ip;
            j_node["p"] = r.port;
            j_node["seen"] = r.last_seen;
            j_node["super"] = r.is_supernode; // <--- THÊM DÒNG NÀY
            j_root["nodes"].push_back(j_node);
        }

        ofstream f(INTERNAL_DB_PATH);
        if (f.is_open()) {
            f << j_root.dump(4); // Pretty print (thụt đầu dòng 4 spaces cho đẹp)
            f.close();
        }
    }

public:
    RoutingTable() {
        load_db();
    }

   void load_db() {
        // 1. LUÔN LUÔN load danh bạ cũ bên trong trước (để giữ danh sách bạn bè)
        if (fs::exists(INTERNAL_DB_PATH)) {
            ifstream f(INTERNAL_DB_PATH);
            json j; f >> j;
            for (auto& item : j["nodes"]) {
                NodeRoute r;
                r.node_id = item["id"]; r.ip = item["ip"]; r.port = item["p"];
                r.last_seen = item.contains("seen") ? (time_t)item["seen"] : time(0);
                r.is_supernode = item.value("super", false);
                table[r.node_id] = r; // Nạp vào RAM
            }
        }

        // 2. NẾU THẤY file bên ngoài (File mồi/Cập nhật) -> Đọc để ĐÈ lên hoặc THÊM mới
        if (fs::exists(EXTERNAL_DB_PATH)) {
            cout << "[ROUTE] Tim thay file 'nodes.json' moi. Dang cap nhat danh ba...\n";
            ifstream f(EXTERNAL_DB_PATH);
            json j; f >> j;
            for (auto& item : j["nodes"]) {
                string id = item["id"];
                table[id].node_id = id;
                table[id].ip = item["ip"];
                table[id].port = item.contains("p") ? (int)item["p"] : (int)item["port"]; // Đọc cả "p" hoặc "port"
                table[id].is_supernode = item.value("super", false); // QUAN TRỌNG: Đọc trường super
                table[id].last_seen = time(0);
            }
            f.close();

            // 3. Sau khi "ăn" xong dữ liệu bên ngoài, lưu tất cả vào bên trong cho an toàn
            save_db();

            // 4. Đổi tên file ngoài thành .bak để lần sau nó không "nhai" lại cái cũ này nữa
            if (fs::exists(EXTERNAL_DB_PATH + ".bak")) fs::remove(EXTERNAL_DB_PATH + ".bak");
            fs::rename(EXTERNAL_DB_PATH, EXTERNAL_DB_PATH + ".bak");
        }
    }
    void update_route(string id, string ip, int port, bool is_relayed = false) {
        if (id.empty()) return;

        // 1. Cập nhật vào RAM (Để dùng ngay lập tức)
        NodeRoute& route = table[id];
        route.node_id = id; 
        
        if (!is_relayed) {
            route.ip = ip; 
            route.port = port;
        }
        
        route.is_direct = !is_relayed; // Nếu là Relay thì không phải Direct
        route.last_seen = time(0);

        // 2. CHỈ LƯU XUỐNG ĐĨA NẾU LÀ DIRECT (QUAN TRỌNG)
        // Nếu là Relay (is_relayed = true), ta chỉ giữ trong RAM.
        // Tuyệt đối không lưu xuống file để tránh lần sau bật lên bị trỏ nhầm vào Admin.
        if (!is_relayed) {
            save_db(); 
        }
    }

    bool get_route(string id, string& out_ip, int& out_port, bool& out_is_direct) {
        if (table.find(id) != table.end()) {
            out_ip = table[id].ip; 
            out_port = table[id].port; 
            // Lấy cái cờ ra để xem là Direct hay Relay
            out_is_direct = table[id].is_direct; 
            return true;
        }
        return false;
    }
    
    // Giữ lại hàm cũ (Overload) để đỡ phải sửa mấy chỗ không quan trọng khác
    bool get_route(string id, string& out_ip, int& out_port) {
        bool dummy;
        return get_route(id, out_ip, out_port, dummy);
    }

    bool get_bootstrap(string& out_ip, int& out_port) {
        if (table.empty()) return false;

        // Ưu tiên tìm SuperNode trước
        for (auto const& [id, route] : table) {
            if (route.is_supernode) {
                out_ip = route.ip;
                out_port = route.port;
                // cout << "[DEBUG] Da tim thay SuperNode: " << id << endl;
                return true;
            }
        }

        // Nếu không có SuperNode nào, ta mới dùng phương án dự phòng là lấy node đầu tiên
        auto it = table.begin();
        out_ip = it->second.ip;
        out_port = it->second.port;
        return true;
    }

    void print_routing_table() {
        if (table.empty()) {
            printf("\n[ROUTE] Danh ba trong (Empty).\n"); return;
        }

        printf("\n==================== [ GLOBAL ROUTING TABLE (JSON) ] ===================\n");
        printf("| %-20s | %-21s | %-12s |\n", "NODE ID", "ADDRESS", "LAST SEEN");
        printf("|----------------------|-----------------------|--------------|\n");
        
        time_t now = time(0);
        for (const auto& pair : table) {
            const NodeRoute& r = pair.second;
            string short_id = r.node_id.substr(0, 18);
            string addr = r.ip + ":" + to_string(r.port);
            long diff = now - r.last_seen;
            
            string time_str;
            if (diff < 60) time_str = to_string(diff) + "s ago";
            else if (diff < 3600) time_str = to_string(diff/60) + "m ago";
            else time_str = "> 1h ago";

            printf("| %-20s | %-21s | %-12s |\n", short_id.c_str(), addr.c_str(), time_str.c_str());
        }
        printf("========================================================================\n");
    }

    // 1. Hàm kiểm tra một ID bất kỳ có phải là SuperNode không
    bool is_supernode(string id) {
        if (table.find(id) != table.end()) {
            return table[id].is_supernode;
        }
        return false;
    }

    // 2. Hàm giúp Node tự nhận diện "Mình là ai?" ngay khi khởi động
    bool check_my_role(string my_id) {
        // Làm sạch ID đầu vào để so khớp cho chuẩn
        string clean_my_id = my_id;
        if (clean_my_id.length() > 16) clean_my_id = clean_my_id.substr(0, 16);

        if (table.find(clean_my_id) != table.end()) {
            if (table[clean_my_id].is_supernode) {
                cout << "\033[1;32m[SYSTEM] ROLE: SUPER NODE (MIDDLEMAN)\033[0m\n";
                return true;
            }
        }
        cout << "\033[1;34m[SYSTEM] ROLE: NORMAL NODE (CLIENT)\033[0m\n";
        return false;
    }

    vector<SuperNodeInfo> get_all_supernodes() {
        vector<SuperNodeInfo> list;
        for (auto const& [id, route] : table) {
            if (route.is_supernode) {
                list.push_back({id, route.ip, route.port});
            }
        }
        return list;
    }

    vector<NodeRoute> get_all_nodes() {
        vector<NodeRoute> list;
        for (auto const& [id, route] : table) {
            list.push_back(route);
        }
        return list;
    }

    void clean_temporary_nodes() {
        //cout << "[CLEANUP] Dang loc bo cache rac (Giữ lai SuperNode)...\n";
        
        auto it = table.begin();
        while (it != table.end()) {
            // Logic: Nếu KHÔNG PHẢI SuperNode -> Xóa khỏi RAM
            if (!it->second.is_supernode) {
                it = table.erase(it); 
            } else {
                ++it; // SuperNode -> Giữ lại
            }
        }

        // Sau khi RAM đã sạch (chỉ còn SuperNode), gọi save_db để ghi đè file cũ
        // Lúc này file nodes.json sẽ chỉ chứa danh sách SuperNode.
        save_db();
        
        //cout << "[CLEANUP] Xong! Cache hien tai chi chua cac SuperNode co dinh.\n";
    }
};

#endif