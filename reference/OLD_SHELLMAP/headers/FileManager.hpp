#ifndef FILE_MANAGER_HPP
#define FILE_MANAGER_HPP

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <set>
#include <map>
#include <cstring>
#include <openssl/sha.h>
#include "json.hpp"
#include "base64.hpp" // Đảm bảo bạn đã có file base64.hpp (hoặc dùng hàm trong CryptoCore)

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std;

class FileManager {
private:
    const string ROOT_DIR = "shellmap/shared/";
    const string DOWN_DIR = "shellmap/downloads/"; // [MỚI] Kho chứa hàng tải về

    // --- CẤU HÌNH BẢO MẬT ---
    bool config_allow_upload = true;          // Bật/Tắt upload
    uint64_t config_max_size = 50 * 1024 * 1024; // Max 50MB
    
    // Danh sách đuôi file cho phép (Whitelist)
    set<string> whitelist = {
        ".txt", ".log", ".md", ".json",       // Text
        ".jpg", ".jpeg", ".png", ".gif",      // Image
        ".mp4", ".mp3", ".wav",               // Media
        ".zip", ".rar", ".pdf" , ".mml"                // Archive , web
    };

    // Track file hashes for verification
    // Key: filename, Value: SHA-256 hash (hex string)
    map<string, string> file_hashes_;
    
    // Track download state for multi-chunk transfers
    struct DownloadState {
        uint64_t total_size;
        uint64_t received_bytes;
        string expected_hash;
        map<uint64_t, string> chunk_hashes; // chunk_offset -> SHA-256
        bool is_complete = false;
    };
    map<string, DownloadState> download_states_;

public:
    FileManager() {
        if (!fs::exists(ROOT_DIR)) fs::create_directories(ROOT_DIR);
        if (!fs::exists(DOWN_DIR)) fs::create_directories(DOWN_DIR); // [MỚI] Tạo kho
        // Tạo vài file giả để test lệnh ls
        string welcome_path = ROOT_DIR + "welcome.txt";
        if (!fs::exists(welcome_path)) {
            ofstream(welcome_path) << "Welcome to ShellMap Node! (Edit me if you want)";
        }
    }

    // Lệnh LS: Trả về danh sách file dạng JSON
    json handle_ls() {
        json files = json::array();
        try {
            for (const auto& entry : fs::directory_iterator(ROOT_DIR)) {
                if (entry.is_regular_file()) {
                    files.push_back({
                        {"n", entry.path().filename().string()}, // Tên file
                        {"s", entry.file_size()}                 // Kích thước
                    });
                }
            }
            return {{"status", "ok"}, {"files", files}};
        } catch (...) {
            return {{"status", "error"}, {"msg", "Loi doc thu muc"}};
        }
    }

    // [MỚI 1] Lấy kích thước file (Để trả lời Meta Request)
    long get_file_size(string filename) {
        string path = ROOT_DIR + filename;
        if (!fs::exists(path)) return -1;
        return fs::file_size(path);
    }

    // [MỚI 2] Đọc 1 miếng file (CHUNK READ)
    // Trả về dữ liệu nhị phân (vector<uint8_t>)
    vector<uint8_t> read_file_chunk(string filename, uint64_t offset, size_t len) {
        string path = ROOT_DIR + filename;
        ifstream f(path, ios::binary);
        if (!f) return {};

        f.seekg(offset);
        if (f.fail()) return {}; // Nếu offset vượt quá file

        vector<uint8_t> buffer(len);
        f.read((char*)buffer.data(), len);
        
        // Resize lại buffer nếu đọc được ít hơn yêu cầu (ví dụ đoạn cuối file)
        buffer.resize(f.gcount());
        return buffer;
    }

    // [MỚI 3] Ghi 1 miếng file (CHUNK WRITE)
    // Dùng để ráp file khi tải về
   bool write_file_chunk(string filename, uint64_t offset, const vector<uint8_t>& data) {
        // Lưu vào shellmap/downloads/
        string path = DOWN_DIR + filename;
        
        fstream f;
        if (!fs::exists(path)) {
            f.open(path, ios::binary | ios::out);
        } else {
            f.open(path, ios::binary | ios::in | ios::out);
        }
        
        if (!f) return false;
        f.seekp(offset);
        f.write((char*)data.data(), data.size());
        return true;
    }

    // --- KIỂM TRA BẢO MẬT (SECURITY CHECK) ---
    // Trả về: "" nếu OK, hoặc chuỗi báo lỗi nếu vi phạm
    string check_upload_policy(string filename, uint64_t filesize) {
        // 1. Check quyền
        if (!config_allow_upload) return "Upload bi tu choi boi Server (Config blocked).";

        // 2. Check kích thước
        if (filesize > config_max_size) return "File qua lon! Max allow: 50MB.";

        // 3. Chuẩn hóa tên file (Lower case) để check extension
        string lower_name = filename;
        transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

        // 4. Check Double Extension (Chống trò mèo .png.php)
        // Logic: Đếm số dấu chấm, hoặc tìm chuỗi nguy hiểm
        if (lower_name.find(".php") != string::npos || 
            lower_name.find(".exe") != string::npos ||
            lower_name.find(".sh") != string::npos || 
            lower_name.find(".py") != string::npos) {
            return "Phat hien ten file nguy hiem (Blacklist)!";
        }

        // 5. Check Whitelist Extension
        size_t last_dot = lower_name.find_last_of(".");
        if (last_dot == string::npos) return "File khong co duoi mo rong!";
        
        string ext = lower_name.substr(last_dot);
        if (whitelist.find(ext) == whitelist.end()) {
            return "Duoi file '" + ext + "' khong nam trong Whitelist!";
        }

        return ""; // OK, Pass hết
    }

    // Ghi file vào kho Shared (Khi người khác Upload lên mình)
    bool write_upload_chunk(string filename, uint64_t offset, const vector<uint8_t>& data) {
        string path = ROOT_DIR + filename; // Lưu vào folder Shared luôn
        
        fstream f;
        if (!fs::exists(path)) {
            f.open(path, ios::binary | ios::out);
        } else {
            f.open(path, ios::binary | ios::in | ios::out);
        }
        
        if (!f) return false;
        f.seekp(offset);
        f.write((char*)data.data(), data.size());
        return true;
    }
    
    // Hàm hỗ trợ lệnh 'me' để lấy đường dẫn tuyệt đối
    string get_download_path() {
        return fs::absolute(DOWN_DIR).string();
    }

    void set_upload_allow(bool allow) {
        config_allow_upload = allow;
    }

    void set_max_size_mb(int mb) {
        config_max_size = (uint64_t)mb * 1024 * 1024; // Đổi MB sang Bytes
    }

    // Hàm lấy thông tin để hiển thị
    string get_config_status() {
        string status = "\n--- NODE CONFIGURATION ---\n";
        status += "Upload Permission: " + string(config_allow_upload ? "[ON] Allowed" : "[OFF] Blocked") + "\n";
        status += "Max Upload Size  : " + to_string(config_max_size / (1024 * 1024)) + " MB\n";
        status += "Whitelist Exts   : .txt, .jpg, .png, .mp4, .zip, .pdf...\n";
        status += "--------------------------\n";
        return status;
    }

    // --- SHA-256 HASH VERIFICATION (NEW) ---

    /**
     * @brief Tính SHA-256 hash của 1 chunk
     * @param data Chunk data
     * @return Hex string of SHA-256
     */
    string calculate_chunk_hash(const vector<uint8_t>& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, data.data(), data.size());
        SHA256_Final(hash, &sha256);

        string result;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", hash[i]);
            result += buf;
        }
        return result;
    }

    /**
     * @brief Tính SHA-256 hash của toàn bộ file
     * @param path File path
     * @return Hex string of SHA-256
     */
    string calculate_file_hash(const string& path) {
        ifstream f(path, ios::binary);
        if (!f) return "";

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        const size_t BUFFER_SIZE = 4096;
        char buffer[BUFFER_SIZE];
        while (f.read(buffer, BUFFER_SIZE)) {
            SHA256_Update(&sha256, (unsigned char*)buffer, f.gcount());
        }
        f.close();

        SHA256_Final(hash, &sha256);

        string result;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", hash[i]);
            result += buf;
        }
        return result;
    }

    /**
     * @brief Verify chunk hash và update download state
     * @param filename Filename being downloaded
     * @param offset Chunk offset
     * @param chunk_hash Expected hash (từ sender)
     * @param data Chunk data received
     * @return true nếu hash match, false nếu sai
     */
    bool verify_chunk_hash(
        const string& filename,
        uint64_t offset,
        const string& chunk_hash,
        const vector<uint8_t>& data
    ) {
        string calculated = calculate_chunk_hash(data);
        return calculated == chunk_hash;
    }

    /**
     * @brief Register download and set expected file hash
     * @param filename Filename
     * @param total_size Total file size
     * @param expected_hash Expected SHA-256 of full file
     */
    void register_download(
        const string& filename,
        uint64_t total_size,
        const string& expected_hash
    ) {
        DownloadState& state = download_states_[filename];
        state.total_size = total_size;
        state.received_bytes = 0;
        state.expected_hash = expected_hash;
        state.is_complete = false;
    }

    /**
     * @brief Verify full file hash sau khi download hoàn tất
     * @param filename Filename
     * @return true nếu hash match, false nếu corrupted
     */
    bool verify_file_complete(const string& filename) {
        string path = DOWN_DIR + filename;
        if (!fs::exists(path)) return false;

        auto it = download_states_.find(filename);
        if (it == download_states_.end()) return false;

        string calculated = calculate_file_hash(path);
        if (calculated != it->second.expected_hash) {
            // Hash mismatch - delete corrupted file
            fs::remove(path);
            download_states_.erase(it);
            return false;
        }

        download_states_[filename].is_complete = true;
        return true;
    }
};

#endif