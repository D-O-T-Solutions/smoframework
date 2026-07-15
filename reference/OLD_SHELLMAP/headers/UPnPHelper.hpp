#ifndef UPNP_HELPER_HPP
#define UPNP_HELPER_HPP

#include <iostream>
#include <string>
#include <cstring>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <array>
#include <memory>
#include <vector>
#include <ifaddrs.h> // Thư viện để lấy IP LAN
#include <netinet/in.h> 
#include <arpa/inet.h>

using namespace std;

class UPnPHelper {
private:
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lan_addr[64];  // IP LAN của mình (192.168.x.x)
    char pub_addr[64];  // IP Public của nhà mạng
    string port_str;
    bool is_mapped = false;


    const vector<string> ip_services = {
        "ifconfig.me",          // Rất nổi tiếng
        "api.ipify.org",        // Cực nhanh
        "eth0.me",              // Gọn nhẹ
        "ident.me",             // Ổn định
        "icanhazip.com",        // Của Rackspace
        "checkip.amazonaws.com" // Của Amazon AWS (Trùm cuối)
    };
    // [MỚI] Hàm dùng lệnh curl để lấy IP thật từ Internet
    string exec_curl(string url) {
        array<char, 128> buffer;
        string result;
        
        // Timeout 2 giây thôi, lỗi là bỏ qua ngay cho nhanh
        string cmd = "curl -s --max-time 2 " + url + " 2>/dev/null"; 
        
        unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (!pipe) return "";
        
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        
        // Xóa ký tự xuống dòng thừa
        while (!result.empty() && (result.back() == '\n' || result.back() == '\r' || result.back() == ' ')) {
            result.pop_back();
        }
        return result;
    }

    // [NÂNG CẤP] Hàm lấy IP đi qua danh sách dự phòng
    string get_robust_public_ip() {
        for (const string& service : ip_services) {
            // cout << "[DEBUG] Thu lay IP tu: " << service << "...\n"; // (Bật nếu muốn debug)
            string ip = exec_curl(service);
            
            // Validate sơ bộ: IP phải có dấu chấm và độ dài hợp lý (7-15 ký tự)
            if (ip.length() >= 7 && ip.length() <= 15 && ip.find('.') != string::npos) {
                // Kiểm tra ký tự lạ (để tránh html lỗi)
                bool valid_chars = true;
                for(char c : ip) {
                    if (!isdigit(c) && c != '.') { valid_chars = false; break; }
                }
                
                if (valid_chars) return ip; // Tìm thấy IP xịn -> Trả về ngay
            }
        }
        return ""; // Thua, không trang nào trả về IP ra hồn
    }

    bool is_private_ip(string ip) {
        // Check sơ bộ các dải IP LAN: 192.168.x.x, 10.x.x.x, 172.16-31.x.x
        if (ip.find("192.168.") == 0) return true;
        if (ip.find("10.") == 0) return true;
        if (ip.find("127.") == 0) return true;
        if (ip.find("172.") == 0) {
            // Check kỹ hơn dải 172.16 - 172.31 nếu cần, nhưng tạm thời cứ return true
            return true; 
        }
        return false;
    }

public:
    string public_ip;
    string local_ip;

    string get_lan_ip() {
        struct ifaddrs *ifAddrStruct = NULL;
        struct ifaddrs *ifa = NULL;
        void *tmpAddrPtr = NULL;
        string final_ip = "127.0.0.1";

        getifaddrs(&ifAddrStruct);

        for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            // Chỉ lấy IPv4
            if (ifa->ifa_addr->sa_family == AF_INET) { 
                tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                string ip(addressBuffer);

                // Bỏ qua Localhost (127.0.0.1)
                if (ip != "127.0.0.1") {
                    final_ip = ip;
                    // Ưu tiên lấy IP bắt đầu bằng 192.168 hoặc 10. (LAN Class)
                    if (ip.find("192.168.") == 0 || ip.find("10.") == 0) break;
                }
            }
        }
        if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);
        return final_ip;
    }

    // 1. Thử mở Port (Map Port)
    int try_map_port(int port) {
        port_str = to_string(port);
        cout << "[UPnP] Checking Port " << port << "...\n";
        
        // ... (Đoạn Discover và lấy IP giữ nguyên) ...
        int error = 0;
        struct UPNPDev *devlist = upnpDiscover(2000, NULL, NULL, 0, 0, 2, &error);
        if (!devlist) return 1; // Lỗi mạng

        int status = UPNP_GetValidIGD(devlist, &urls, &data, lan_addr, sizeof(lan_addr));
        freeUPNPDevlist(devlist);
        if (status == 0) return 1; // Lỗi Router

        if (UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, pub_addr) != 0) return 1;
        public_ip = string(pub_addr);

        // --- MAPPING ---
        // [MỚI] Nếu IP từ Router là IP nội bộ -> Tự check lại qua Internet
        if (public_ip.empty() || is_private_ip(public_ip)) {
            string real_ip = get_robust_public_ip();
            
            if (!real_ip.empty()) {
                public_ip = real_ip; // Cập nhật hàng xịn
            }
        }
        // Thử Map UDP
        int r_udp = UPNP_AddPortMapping(
            urls.controlURL, data.first.servicetype,
            port_str.c_str(), port_str.c_str(), lan_addr,
            "ShellMap UDP", "UDP", NULL, NULL
        );

        if (r_udp == UPNPCOMMAND_SUCCESS) {
            cout << "[UPnP] [SUCCESS] Port " << port << " OK! (Public IP: " << public_ip << ")\n";
            is_mapped = true;
            return 0; // Thành công
        } else if (r_udp == 718 || r_udp == 729) { 
            // 718: ConflictInMappingEntry (Đã có thằng khác dùng)
            cout << "[UPnP] [BUSY] Port " << port << " other working on, please change port!\n";
            return 2; // Báo trùng
        } else {
             cout << "[UPnP] [FAIL] Router Error code: " << r_udp << ".\n";
             return 1; // Lỗi khác
        }
    }

    // 2. Xóa Mapping khi tắt chương trình (Dọn dẹp)
    void remove_mapping() {
        if (!is_mapped) return;
        UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port_str.c_str(), "UDP", NULL);
        UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port_str.c_str(), "TCP", NULL);
        cout << "[UPnP] Removed Port Mapping on Router.\n";
        FreeUPNPUrls(&urls);
    }
    
    ~UPnPHelper() {
        remove_mapping();
    }
};

#endif