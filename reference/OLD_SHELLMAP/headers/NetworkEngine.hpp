// headers/NetworkEngine.hpp
#ifndef NETWORK_ENGINE_HPP
#define NETWORK_ENGINE_HPP

#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h> 
#include <netinet/in.h>

#include "Protocol.hpp"

using namespace std;

/**
 * @class NetworkEngine
 * @brief UDP network operations with IPv6 dual-stack support
 * 
 * Features:
 * - IPv6 dual-stack socket (supports both IPv4 and IPv6)
 * - True source discovery from kernel recvfrom()
 * - Anti-NAT/GNAT spoofing (never trust IP/Port in packet payload)
 */
class NetworkEngine {
private:
    int sockfd = -1;
    int port;
    bool ipv6_enabled = false;

public:
    // Khởi tạo Socket UDP (Dual-stack IPv6)
    bool init(int port_num) {
        this->port = port_num;
        
        // Try IPv6 dual-stack first
        sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            // Fallback to IPv4 only
            cout << "[NET] IPv6 not available, falling back to IPv4..." << endl;
            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd < 0) return false;
        } else {
            // IPv6 socket created successfully
            ipv6_enabled = true;
            
            // Disable IPV6_V6ONLY to support both IPv4 and IPv6
            int opt = 0;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
                cerr << "[NET] Warning: Failed to disable IPV6_V6ONLY" << endl;
            }
        }

        // Cho phép tái sử dụng Port
        int opt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (ipv6_enabled) {
            struct sockaddr_in6 addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin6_family = AF_INET6;
            addr.sin6_addr = in6addr_any;
            addr.sin6_port = htons(port);

            if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
                perror("IPv6 bind failed");
                close(sockfd);
                sockfd = -1;
                return false;
            }
        } else {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY; 
            addr.sin_port = htons(port);

            if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
                perror("IPv4 bind failed");
                return false;
            }
        }

        // Bỏ comment dòng này nếu muốn Non-blocking (Tốt cho Event Loop sau này)
        // int flags = fcntl(sockfd, F_GETFL, 0);
        // fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        cout << "[NET] Socket " << (ipv6_enabled ? "IPv6 dual-stack" : "IPv4") 
             << " bound to port " << port << endl;
        return true;
    }

    // Gửi gói tin (hỗ trợ IPv4 và IPv6)
    bool send_packet(const PacketHeader& hdr, const std::vector<uint8_t>& payload, const std::string& ip, int dest_port) {
        std::vector<uint8_t> buffer;
        buffer.resize(sizeof(PacketHeader) + payload.size());
        
        memcpy(buffer.data(), &hdr, sizeof(PacketHeader));
        if (!payload.empty()) {
            memcpy(buffer.data() + sizeof(PacketHeader), payload.data(), payload.size());
        }

        // Cố gắng parse IP như IPv6 trước, rồi fallback IPv4
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr* dest_addr = nullptr;
        socklen_t addr_len = 0;

        if (inet_pton(AF_INET6, ip.c_str(), &addr6.sin6_addr) > 0) {
            // IPv6 address
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(dest_port);
            inet_pton(AF_INET6, ip.c_str(), &addr6.sin6_addr);
            dest_addr = (struct sockaddr*)&addr6;
            addr_len = sizeof(addr6);
        } else if (inet_pton(AF_INET, ip.c_str(), &addr4.sin_addr) > 0) {
            // IPv4 address
            memset(&addr4, 0, sizeof(addr4));
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(dest_port);
            inet_pton(AF_INET, ip.c_str(), &addr4.sin_addr);
            dest_addr = (struct sockaddr*)&addr4;
            addr_len = sizeof(addr4);
        } else {
            cerr << "[NET] Invalid IP address: " << ip << endl;
            return false;
        }

        ssize_t n = sendto(sockfd, buffer.data(), buffer.size(), 0, dest_addr, addr_len);
        return (n > 0);
    }

    /**
     * @brief Nhận gói tin với True Source Discovery
     * 
     * CRITICAL: Sử dụng sender_addr từ kernel recvfrom() để xác định IP/Port thực tế.
     * NEVER tin vào IP/Port trong payload packet.
     */
    int recv_packet(PacketHeader& out_hdr, std::vector<uint8_t>& out_payload, struct sockaddr_in& sender_info) {
        char buffer[2048];
        
        // Sử dụng sockaddr_storage để handle cả IPv4 và IPv6
        struct sockaddr_storage sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                           (struct sockaddr*)&sender_addr, &addr_len);
        
        if (n < (ssize_t)sizeof(PacketHeader)) {
            return -1;
        }

        // Tách Header
        memcpy(&out_hdr, buffer, sizeof(PacketHeader));
        
        // Validate Magic Bytes
        if (out_hdr.magic[0] != 'S' || out_hdr.magic[1] != 'M') {
            return -1;
        }

        // === TRUE SOURCE DISCOVERY ===
        // Extract actual IP:Port từ kernel recvfrom(), KHÔNG từ packet payload
        memset(&sender_info, 0, sizeof(sender_info));  // Initialize to zeros
        sender_info.sin_family = AF_INET;
        
        if (sender_addr.ss_family == AF_INET6) {
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&sender_addr;
            
            // Check if this is an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            // IPv4-mapped addresses have format: 0:0:0:0:0:ffff:a.b.c.d (in binary: 10 bytes of 0, 2 bytes of ffff, then 4 bytes of IPv4)
            const uint8_t* addr_bytes = (const uint8_t*)&addr6->sin6_addr;
            bool is_ipv4_mapped = (
                addr_bytes[0] == 0 && addr_bytes[1] == 0 &&
                addr_bytes[2] == 0 && addr_bytes[3] == 0 &&
                addr_bytes[4] == 0 && addr_bytes[5] == 0 &&
                addr_bytes[6] == 0 && addr_bytes[7] == 0 &&
                addr_bytes[8] == 0 && addr_bytes[9] == 0 &&
                addr_bytes[10] == 0xff && addr_bytes[11] == 0xff
            );
            
            if (is_ipv4_mapped) {
                // Extract the IPv4 address from the last 4 bytes
                sender_info.sin_addr.s_addr = *(uint32_t*)&addr_bytes[12];
            } else {
                // Pure IPv6 address - try to convert to IPv4 string and back
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &addr6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
                if (inet_pton(AF_INET, ip_str, &sender_info.sin_addr) <= 0) {
                    sender_info.sin_addr.s_addr = INADDR_ANY;
                }
            }
            sender_info.sin_port = addr6->sin6_port;
        } else {
            struct sockaddr_in* addr4 = (struct sockaddr_in*)&sender_addr;
            sender_info.sin_addr = addr4->sin_addr;  // Actual IP from kernel
            sender_info.sin_port = addr4->sin_port;  // Actual port from kernel
        }
        // NOTE: Never use out_hdr.sender_id IP/Port for routing!
        // Always use sender_info (kernel recvfrom result)

        // Tách Payload
        int payload_size = n - sizeof(PacketHeader);
        if (payload_size > 0) {
            out_payload.resize(payload_size);
            memcpy(out_payload.data(), buffer + sizeof(PacketHeader), payload_size);
        } else {
            out_payload.clear();
        }

        return n;
    }
    
    int get_socket_fd() { return sockfd; }
    
    int get_actual_port() {
        // Get the actual port that socket is bound to (kernel-assigned if we didn't specify)
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
        socklen_t addr_len;
        
        if (ipv6_enabled) {
            addr_len = sizeof(addr6);
            if (getsockname(sockfd, (struct sockaddr*)&addr6, &addr_len) == 0) {
                return ntohs(addr6.sin6_port);
            }
        } else {
            addr_len = sizeof(addr);
            if (getsockname(sockfd, (struct sockaddr*)&addr, &addr_len) == 0) {
                return ntohs(addr.sin_port);
            }
        }
        return port;  // Fallback to requested port
    }
    
    bool is_ipv6_enabled() { return ipv6_enabled; }
    
    void close_socket() {
        if (sockfd > 0) close(sockfd);
    }
};

#endif