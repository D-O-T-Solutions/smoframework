#ifndef NODE_INITIALIZER_HPP
#define NODE_INITIALIZER_HPP

#include <iostream>
#include <filesystem>
#include <fstream>
#include <iomanip> // Cần cho std::setw, std::hex
#include <vector>
#include <sstream> // Cần cho stringstream

#include "json.hpp"
#include "CryptoCore.hpp" // Chứa hàm sinh khóa

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std;

// ==========================================
// ANSI COLOR CODES
// ==========================================
#define COLOR_RESET     "\033[0m"
#define COLOR_CYAN      "\033[36m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_RED       "\033[31m"
#define COLOR_MAGENTA   "\033[35m"
#define COLOR_BRIGHT_GREEN   "\033[1;32m"
#define COLOR_BRIGHT_CYAN    "\033[1;36m"

// Cấu trúc chứa mọi thông tin của Node sau khi init xong
struct NodeContext {
    string node_id;         
    string falcon_pub;      
    string falcon_priv;     
    string kyber_pub;       
    string kyber_priv;      
    int port;
    bool is_relay;
    bool is_admin = false; // Mặc định tất cả là Client
    string public_ip;      // NAT public IP (detected from SuperNode)
    int public_port;       // NAT public port (detected from SuperNode)
};

class NodeInitializer {
private:
    const string SYS_DIR = "shellmap/system/";
    const string CFG_FILE = "shellmap/system/config.json";

    // Hàm tiện ích: Đọc toàn bộ file vào string
    string read_key_file(string path) {
        ifstream ifs(path, ios::binary | ios::ate);
        if (!ifs) return "";
        auto size = ifs.tellg();
        string str(size, '\0');
        ifs.seekg(0);
        ifs.read(&str[0], size);
        return str;
    }

    // Hàm băm SHA256 tạo NodeID (Trả về toàn bộ 64 ký tự Hex - KHÔNG CẮT)
    string derive_node_id(const string& pub_key) {
        string hash_bytes = CryptoCore::sha256(pub_key);
        // Convert 32 binary bytes to 64-char hex string
        return CryptoCore::bytes_to_hex(hash_bytes);
    }

public:
    NodeContext context;

    // Static method for static initialization across multiple calls
    static NodeContext& init() {
        static NodeInitializer instance;
        instance.run();
        return instance.context;
    }

    void run() {
        // 1. Tạo cấu trúc thư mục
        if (!fs::exists("shellmap")) fs::create_directories("shellmap");
        if (!fs::exists("shellmap/shared")) fs::create_directories("shellmap/shared");
        if (!fs::exists("shellmap/downloads")) fs::create_directories("shellmap/downloads");
        if (!fs::exists(SYS_DIR)) fs::create_directories(SYS_DIR);

        string f_pub_path = SYS_DIR + "falcon_pub.key";
        string f_priv_path = SYS_DIR + "falcon_priv.key";
        string k_pub_path = SYS_DIR + "kyber_pub.key";
        string k_priv_path = SYS_DIR + "kyber_priv.key";
        
        // 2. Kiểm tra khóa (Identity) - Nếu thiếu thì sinh mới
        if (!fs::exists(f_priv_path) || !fs::exists(k_priv_path)) {
            cout << "\n" << COLOR_BRIGHT_GREEN << "[INIT] First run detected. Generating cryptographic keys..." << COLOR_RESET << "\n";
            
            // --- Sinh Falcon ---
            string f_pub, f_priv;
            if (!CryptoCore::generate_falcon_keypair(f_pub, f_priv)) {
                cerr << COLOR_RED << "[FATAL] Failed to generate Falcon keypair!" << COLOR_RESET << "\n";
                exit(1);
            }
            
            // --- Sinh Kyber ---
            string k_pub, k_priv;
            if (!CryptoCore::generate_kyber_keypair(k_pub, k_priv)) {
                cerr << COLOR_RED << "[FATAL] Failed to generate Kyber keypair!" << COLOR_RESET << "\n";
                exit(1);
            }
            
            // Lưu xuống đĩa
            ofstream(f_pub_path, ios::binary) << f_pub;
            ofstream(f_priv_path, ios::binary) << f_priv;
            ofstream(k_pub_path, ios::binary) << k_pub;
            ofstream(k_priv_path, ios::binary) << k_priv;
            
            cout << COLOR_GREEN << "✓ Identity created successfully." << COLOR_RESET << "\n";
        }

        // 3. Load khóa lên RAM
        context.falcon_pub = read_key_file(f_pub_path);
        context.falcon_priv = read_key_file(f_priv_path);
        context.kyber_pub = read_key_file(k_pub_path);
        context.kyber_priv = read_key_file(k_priv_path);
        
        if (context.falcon_pub.empty() || context.kyber_pub.empty()) {
            cerr << COLOR_RED << "[FATAL] Failed to read key files. Please delete shellmap/system and restart." << COLOR_RESET << "\n";
            exit(1);
        }

        // 4. Tính toán NodeID từ Falcon public key
        context.node_id = derive_node_id(context.falcon_pub);

        // 5. Kiểm tra Config
        if (!fs::exists(CFG_FILE)) {
            create_default_config();
        }
        load_config();
        
        cout << COLOR_CYAN << "[INIT] Node initialized: " << context.node_id.substr(0, 16) << "..." 
             << " (Port: " << context.port << ", Relay: " << (context.is_relay ? "YES" : "NO") << ")" 
             << COLOR_RESET << "\n";
    }

    void create_default_config() {
        cout << "\n" << COLOR_BRIGHT_CYAN << "=== ShellMap Initial Setup ===" << COLOR_RESET << "\n";
        cout << "Answer a few questions to complete setup:\n\n";
        
        int port = 5555;
        string port_input;
        char relay_choice;
        
        cout << COLOR_YELLOW << "1. Listen Port (default 5555 for server, 0 for auto): " << COLOR_RESET;
        getline(cin, port_input);
        if (!port_input.empty()) {
            try {
                port = stoi(port_input);
            } catch (...) {
                port = 5555;
            }
        }
        
        if (port == 0) {
            port = 0;  // OS will auto-assign
            cout << COLOR_GREEN << "   → Auto-port mode enabled (OS will assign port)" << COLOR_RESET << "\n";
        }

        cout << COLOR_YELLOW << "2. Enable Relay mode? (y/n, default: n): " << COLOR_RESET;
        string relay_input;
        getline(cin, relay_input);
        relay_choice = relay_input.empty() ? 'n' : relay_input[0];

        json cfg = {
            {"port", port},
            {"is_relay", (relay_choice == 'y' || relay_choice == 'Y')},
            {"storage_limit_mb", 1024},
            {"node_name", "Anonymous_Node"}
        };

        ofstream o(CFG_FILE);
        o << setw(4) << cfg << endl;
        cout << COLOR_GREEN << "✓ Configuration saved to " << CFG_FILE << COLOR_RESET << "\n";
    }

    void load_config() {
        ifstream i(CFG_FILE);
        json cfg;
        if (i.good()) {
            i >> cfg;
            context.port = cfg.value("port", 5555);
            context.is_relay = cfg.value("is_relay", false);
        } else {
            // Fallback nếu file lỗi
            context.port = 5555;
            context.is_relay = false;
        }
    }
};

#endif