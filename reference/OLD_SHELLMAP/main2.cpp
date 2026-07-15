#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <sstream>
#include <cstring>
#include <sys/select.h> // Thư viện cho select()

#include "NodeInitializer.hpp"
#include "NetworkEngine.hpp"
#include "CryptoCore.hpp"
#include "Protocol.hpp"
#include "FileManager.hpp" // 
#include "UPnPHelper.hpp"
#include "RoutingTable.hpp"
#include "base64.hpp"

using namespace std;

FileManager file_mgr;      // <--- Khai báo toàn cục
RoutingTable route_table;

bool is_relay_mode = false; // Mặc định là OFF (Mode Live)

// --- QUẢN LÝ PHIÊN ---
struct Session {
    string node_id;
    string aes_key;
    string aes_nonce;
    bool is_established = false;
    // State Handshake
    string temp_ecdh_priv;
    string temp_kyber_ss;
    
    // Thông tin mạng
    string ip;
    int port;
    string handshake_data;   // Gói Hello gốc
    string peer_falcon_pub;  // Key của đối phương (nếu có)
    string temp_signature;   // Chữ ký nhận được (chờ có Key để verify)
};

struct DownloadState {
    string filename;
    uint64_t total_size;
    uint64_t current_offset;
    bool is_active = false; // Đang tải hay rảnh?
    string peer_key;        // Đang tải từ ai?
};

DownloadState dl_state;

struct UploadState {
    string filename;
    uint64_t total_size;
    uint64_t current_offset;
    bool is_uploading = false;
    string peer_key;
};
UploadState up_state;

map<string, Session> session_table; // Key = "IP:Port"
NodeContext my_identity;
NetworkEngine net_engine;

// Biến lưu mục tiêu hiện tại
string current_target = ""; 

// Hàm vẽ dấu nhắc lệnh cho ngầu
void print_prompt() {
    if (current_target.empty()) {
        cout << "shellmap> " << flush;
    } else {
        // Hiện tên mục tiêu đang chọn: shellmap [127.0.0.1:5556]>
        cout << "shellmap \033[1;36m[" << current_target << "]\033[0m> " << flush; 
    }
}

string clean_id(const char* buf, size_t max_len) {
    size_t len = 0;
    while(len < max_len && buf[len] != '\0') {
        len++;
    }
    return string(buf, len);
}

void smart_send(string target_id, string target_ip, int target_port, PacketHeader& hdr, vector<uint8_t>& payload) {
    if (!is_relay_mode) {
        net_engine.send_packet(hdr, payload, target_ip, target_port);
    } else {
        string bs_ip; int bs_port;
        if (route_table.get_bootstrap(bs_ip, bs_port)) {
            // Đóng gói Header + Payload thành 1 string để base64
            string raw_to_encode;
            raw_to_encode.append((char*)&hdr, sizeof(hdr));
            raw_to_encode.append((char*)payload.data(), payload.size());

            // Dùng hàm của Juna
            string b64 = CryptoCore::base64_encode_str(raw_to_encode);

            json box;
            box["target"] = target_id;
            box["data"] = b64;
            string box_str = box.dump();

            PacketHeader relay_hdr;
            memset(&relay_hdr, 0, sizeof(relay_hdr));
            memcpy(relay_hdr.magic, "SM", 2);
            relay_hdr.op_code = OpCode::RELAY_REQ; // RELAY_REQ
            relay_hdr.payload_len = box_str.length();
            memcpy(relay_hdr.sender_id, my_identity.node_id.c_str(), 16);

            vector<uint8_t> relay_payload(box_str.begin(), box_str.end());
            net_engine.send_packet(relay_hdr, relay_payload, bs_ip, bs_port);
        }
    }
}

// --- HÀM TIỆN ÍCH ---
string make_peer_key(string ip, int port) {
    return ip + ":" + to_string(port);
}
string make_peer_key(sockaddr_in& addr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
    return string(ip) + ":" + to_string(ntohs(addr.sin_port));
}

// --- GỬI YÊU CẦU BẮT TAY (Sau khi đã có Key) ---
void initiate_handshake(string target_id,string target_ip, int target_port, string target_kyber_pub) {
    string peer_key = make_peer_key(target_ip, target_port);
    cout << "\n[INFO] Dang bat tay voi " << peer_key << "...\n";

    // 1. Kyber Encaps
    string kyber_ct, kyber_ss;
    if (!CryptoCore::kyber_encaps(target_kyber_pub, kyber_ct, kyber_ss)) {
        cerr << "\n[ERR] Kyber Encaps failed (Key sai?)\n"; return;
    }

    // 2. ECDH
    string ecdh_pub, ecdh_priv;
    CryptoCore::generate_x25519_keypair(ecdh_pub, ecdh_priv);

    // 3. Lưu trạng thái
    Session& sess = session_table[peer_key];
    sess.ip = target_ip;
    sess.port = target_port;
    sess.temp_kyber_ss = kyber_ss;
    sess.temp_ecdh_priv = ecdh_priv;

    // 4. Gửi HELLO
    Payload_Hello hello;
    memset(&hello, 0, sizeof(hello));
    memcpy(hello.kyber_ct, kyber_ct.data(), 768); // Kyber512 CT size = 768
    memcpy(hello.ecdh_pub, ecdh_pub.data(), 32);

    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, "SM", 2);
    hdr.op_code = OpCode::HELLO;
    hdr.payload_len = sizeof(Payload_Hello);
    memcpy(hdr.sender_id, my_identity.node_id.c_str(), 16);

    vector<uint8_t> payload(sizeof(Payload_Hello));
    memcpy(payload.data(), &hello, sizeof(Payload_Hello));

    sess.handshake_data = string((char*)payload.data(), sizeof(Payload_Hello));
    //string hash_client = CryptoCore::base64_encode_str(CryptoCore::sha256(sess.handshake_data));
   //cout << "\n[DEBUG] Client Data Hash (" << sess.handshake_data.size() << " bytes): " << hash_client << endl;

    smart_send(target_id, target_ip, target_port, hdr, payload);
}

// --- GỬI JSON MÃ HÓA (SMART VERSION) ---
// --- GỬI JSON MÃ HÓA (PHIÊN BẢN CÂN ALL KÈO) ---
void send_secure_json(string peer_key, uint8_t op_code, json j_payload) {
    Session* sess_ptr = nullptr;

    // --- [SỬA LẠI ĐỂ FIX LAG KHI RELAY] ---
    // CHIẾN THUẬT: Đảo ngược thứ tự tìm kiếm

    // 1. ƯU TIÊN TÌM THEO NODE ID (Nếu đang ở chế độ Relay)
    // Lý do: Khi Relay, IP lưu trong session là IP Admin (dùng chung cho nhiều người),
    // nên ta không được tin IP, mà phải tin vào Node ID.
    if (is_relay_mode) {
        string clean_input = clean_id(peer_key.c_str(), 16);
        for (auto& [k, s] : session_table) {
            // So khớp Node ID chính xác từng ký tự
            if (clean_id(s.node_id.c_str(), 16) == clean_input) {
                sess_ptr = &s;
                break;
            }
        }
    }

    // 2. TÌM TRỰC DIỆN THEO KEY (IP:Port)
    // (Dùng cho Mode Live hoặc nếu bước 1 chưa tìm thấy)
    if (!sess_ptr) {
        if (session_table.find(peer_key) != session_table.end()) {
            sess_ptr = &session_table[peer_key];
        }
    } 

    // 3. CỨU CÁNH CUỐI CÙNG (Quét toàn bộ map)
    // Phòng trường hợp Juna nhập IP nhưng session lại lưu theo ID, hoặc ngược lại
    if (!sess_ptr) {
        string clean_input = clean_id(peer_key.c_str(), 16); // Dọn sạch input
        
        for (auto& [k, s] : session_table) {
            // A. So khớp Node ID
            if (clean_id(s.node_id.c_str(), 16) == clean_input) {
                sess_ptr = &s;
                break;
            }

            // B. So khớp IP vật lý trong Session
            string current_ip_port = s.ip + ":" + to_string(s.port);
            if (current_ip_port == peer_key) {
                 sess_ptr = &s;
                 break;
            }
        }
    }

    // --- KẾT THÚC TÌM KIẾM ---

    if (!sess_ptr) {
        cout << "[ERR] Chua ket noi voi '" << peer_key << "'. Hay thu id lai.\n"; 
        return;
    }

    Session& sess = *sess_ptr; // Đã tìm thấy!

    if (!sess.is_established) {
        cout << "[ERR] Dang bat tay voi " << sess.node_id.substr(0,8) << ", cho xiu...\n"; return;
    }

    // --- PHẦN MÃ HÓA (GIỮ NGUYÊN) ---
    string plaintext = j_payload.dump();
    PacketHeader hdr; memset(&hdr, 0, sizeof(hdr)); memcpy(hdr.magic, "SM", 2);
    hdr.op_code = op_code; hdr.flags = PacketFlag::ENCRYPTED; 
    memcpy(hdr.sender_id, my_identity.node_id.c_str(), 16); hdr.seq = 0;

    uint16_t estimated_len = plaintext.size() + 16; 
    hdr.payload_len = estimated_len; 
    string aad((char*)&hdr, sizeof(PacketHeader));
    string ciphertext, tag;
    if (!CryptoCore::aes_gcm_encrypt(sess.aes_key, sess.aes_nonce, plaintext, aad, ciphertext, tag)) {
        cout << "[ERR] Ma hoa AES that bai!\n"; return;
    }

    hdr.payload_len = ciphertext.size() + tag.size();
    vector<uint8_t> final_payload(hdr.payload_len);
    memcpy(final_payload.data(), ciphertext.data(), ciphertext.size());
    memcpy(final_payload.data() + ciphertext.size(), tag.data(), tag.size());

    // --- GỬI ĐI ---
    // sess.node_id lúc này chắc chắn đúng, smart_send sẽ tự lo Relay/Direct
    smart_send(sess.node_id, sess.ip, sess.port, hdr, final_payload);
}

// --- XỬ LÝ GÓI TIN ĐẾN ---
void handle_incoming_packet(PacketHeader& hdr, vector<uint8_t>& payload, sockaddr_in& sender) {
    string peer_key = make_peer_key(sender);
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sender.sin_addr), sender_ip, INET_ADDRSTRLEN);
    int sender_port = ntohs(sender.sin_port);
    string sender_node_id = clean_id(hdr.sender_id, 16);

    if (hdr.op_code != OpCode::P2P_FIND_NODE_REQ) {
        // PING luôn là Direct, còn các gói khác phụ thuộc vào mode hiện tại
        bool is_direct = (hdr.op_code == OpCode::PING) ? true : !is_relay_mode;
        
        // Cập nhật vào Routing Table
        route_table.update_route(sender_node_id, sender_ip, sender_port, !is_direct);
    }

    if (hdr.op_code == OpCode::PING) {
        // Chỉ cần cập nhật Route là xong, không cần phản hồi cầu kỳ
        // Giúp Admin/SuperNode biết "thằng này đang online ở IP này"
        string sender_id_clean = clean_id(hdr.sender_id, 16);
        
        // PING mặc định là Direct (kết nối thẳng)
        route_table.update_route(sender_id_clean, sender_ip, sender_port, false);
        
        // cout << "[NET] Received PING from " << sender_id_clean.substr(0,8) << endl; // (Optional debug)
        return; 
    }
    // 1. Xử lý Discovery (WHO_ARE_YOU)
    else if (hdr.op_code == OpCode::WHO_ARE_YOU) {
        cout << "\n[NET] " << peer_key << " hoi danh tinh. Dang tra loi...\n";
        
        // Trả lời IAM kèm Kyber PubKey
        Payload_Iam_Kyber512 iam;
        memset(&iam, 0, sizeof(iam));
        memcpy(iam.kyber_pub, my_identity.kyber_pub.data(), 800); // Copy PubKey của mình

        PacketHeader resp_hdr;
        memset(&resp_hdr, 0, sizeof(resp_hdr));
        memcpy(resp_hdr.magic, "SM", 2);
        resp_hdr.op_code = OpCode::IAM;
        resp_hdr.payload_len = sizeof(Payload_Iam_Kyber512);
        memcpy(resp_hdr.sender_id, my_identity.node_id.c_str(), 16);

        vector<uint8_t> resp_load(sizeof(Payload_Iam_Kyber512));
        memcpy(resp_load.data(), &iam, sizeof(Payload_Iam_Kyber512));

        smart_send(sender_node_id, sender_ip, sender_port, resp_hdr, resp_load);
    }
    
    // 2. Xử lý Discovery Response (IAM)
    // 2. Xử lý Discovery Response (IAM)
    else if (hdr.op_code == OpCode::IAM) {
        if (payload.size() < sizeof(Payload_Iam_Kyber512)) return;
        auto* iam_pkt = (Payload_Iam_Kyber512*)payload.data();
        Session& sess = session_table[peer_key];
        sess.node_id = sender_node_id; // Lưu ID ngay
        route_table.update_route(sess.node_id, sender_ip, sender_port,is_relay_mode);

        string target_pub((char*)iam_pkt->kyber_pub, 800);
        cout << "\n[NET] Nhan Identity tu " << peer_key << ". Bat dau Handshake!\n";
        
        
        // Có Key rồi, bắt tay thôi!
        initiate_handshake(sender_node_id, sender_ip, sender_port, target_pub);
    }

    // 3. Xử lý HELLO (Giống bài trước)
    else if (hdr.op_code == OpCode::HELLO) {
        if (payload.size() < sizeof(Payload_Hello)) return;
        auto* hello_pkt = (Payload_Hello*)payload.data();

        // Decaps Kyber
        string kyber_ct((char*)hello_pkt->kyber_ct, 768);
        string kyber_ss;
        if (!CryptoCore::kyber_decaps(my_identity.kyber_priv, kyber_ct, kyber_ss)) return;

        // Sinh ECDH
        string my_ecdh_pub, my_ecdh_priv;
        CryptoCore::generate_x25519_keypair(my_ecdh_pub, my_ecdh_priv);
        
        // Tính Shared Key
        string client_ecdh_pub((char*)hello_pkt->ecdh_pub, 32);
        string ecdh_ss;
        if (!CryptoCore::compute_x25519_secret(my_ecdh_priv, client_ecdh_pub, ecdh_ss)) return;

        string session_key, session_nonce;
        CryptoCore::derive_hybrid_key(kyber_ss, ecdh_ss, session_key, session_nonce);

        // Lưu Session
        Session& sess = session_table[peer_key];
        sess.node_id = clean_id(hdr.sender_id, 16);
        sess.aes_key = session_key;
        sess.aes_nonce = session_nonce;
        sess.ip = sender_ip;
        sess.port = sender_port;

        // Gửi WELCOME
        Payload_Welcome welcome;
        memset(&welcome, 0, sizeof(welcome));
        memcpy(welcome.ecdh_pub, my_ecdh_pub.data(), 32);
        
        // Ký số (Mock sign payload Hello)
        string data_to_sign((char*)payload.data(), sizeof(Payload_Hello));
        string sig;
        CryptoCore::falcon_sign(my_identity.falcon_priv, data_to_sign, sig);
        welcome.sig_len = (uint16_t)sig.size();
        memcpy(welcome.signature, sig.data(), 666);

       // string hash_server = CryptoCore::base64_encode_str(CryptoCore::sha256(data_to_sign));
    //cout << "\n[DEBUG] Server Sign Hash (" << data_to_sign.size() << " bytes): " << hash_server << endl;

        PacketHeader resp_hdr;
        memset(&resp_hdr, 0, sizeof(resp_hdr));
        memcpy(resp_hdr.magic, "SM", 2);
        resp_hdr.op_code = OpCode::WELCOME;
        resp_hdr.payload_len = sizeof(Payload_Welcome);
        memcpy(resp_hdr.sender_id, my_identity.node_id.c_str(), 16);

        vector<uint8_t> resp_load(sizeof(Payload_Welcome));
        memcpy(resp_load.data(), &welcome, sizeof(Payload_Welcome));
        
        smart_send(sender_node_id, sender_ip, sender_port, resp_hdr, resp_load);
        cout << "\n[NET] Da chap nhan ket noi. Gui WELCOME.\n";

        route_table.update_route(sess.node_id, sender_ip, sender_port,is_relay_mode);

        sess.is_established = true; // <--- Server tự xác nhận: "Tôi đã chấp nhận ông này"

        if (sess.is_established) return;
        cout << "\n[INFO] Session thiet lap thanh cong (Early Trust).\n";
    }

    // 4. Xử lý WELCOME
    else if (hdr.op_code == OpCode::WELCOME) {
        auto* welcome_pkt = (Payload_Welcome*)payload.data();
        if (session_table.find(peer_key) == session_table.end()) return;
        Session& sess = session_table[peer_key];

        string server_ecdh_pub((char*)welcome_pkt->ecdh_pub, 32);
        string ecdh_ss;
        if (!CryptoCore::compute_x25519_secret(sess.temp_ecdh_priv, server_ecdh_pub, ecdh_ss)) return;

        CryptoCore::derive_hybrid_key(sess.temp_kyber_ss, ecdh_ss, sess.aes_key, sess.aes_nonce);
        
        sess.temp_signature = string((char*)welcome_pkt->signature, welcome_pkt->sig_len);
        if (sess.peer_falcon_pub.empty()) {
            cout << "\n[SECURE] Chua co Key cua Server. Dang yeu cau gui Key...\n";
            
            // Gửi gói GET_PUBKEY
            PacketHeader req_hdr;
            memset(&req_hdr, 0, sizeof(req_hdr));
            memcpy(req_hdr.magic, "SM", 2);
            req_hdr.op_code = OpCode::GET_PUBKEY;
            req_hdr.payload_len = 0;
            memcpy(req_hdr.sender_id, my_identity.node_id.c_str(), 16);
            
            vector<uint8_t> empty_payload; // Khai báo một biến cụ thể
            smart_send(sender_node_id, sender_ip, sender_port, req_hdr,empty_payload);
            return; // Dừng lại, đợi Key về mới tính tiếp
        }
        
        if (!sess.handshake_data.empty()) {
             bool is_valid = CryptoCore::falcon_verify(sess.peer_falcon_pub, sess.handshake_data, sess.temp_signature);
             if (!is_valid) {
                cout << "\n[SECURITY ALERT] CHU KY GIA MAO (Reconnect)! Server fake!\n";
                session_table.erase(peer_key);
                return;
             }
             cout << "\n[SECURE] Chu ky Server hop le (Dung Key co san).\n";
        }

        sess.node_id = clean_id(hdr.sender_id, 16);
        
        sess.is_established = true;
        cout << "\n[SUCCESS] === KET NOI THANH CONG VOI " << peer_key << " ===\n";
    }
    
    // --- [SERVER] NHẬN YÊU CẦU LẤY KEY ---
    else if (hdr.op_code == OpCode::GET_PUBKEY) {
        cout << "\n[NET] " << peer_key << " yeu cau lay Public Key.\n";
        
        Payload_PubKey pk_pkt;
        memset(&pk_pkt, 0, sizeof(pk_pkt));
        // Copy Key Falcon-512 (897 bytes) của mình vào
        if (my_identity.falcon_pub.size() >= 897) {
            memcpy(pk_pkt.falcon_pub, my_identity.falcon_pub.data(), 897);
        }

        PacketHeader resp_hdr;
        memset(&resp_hdr, 0, sizeof(resp_hdr));
        memcpy(resp_hdr.magic, "SM", 2);
        resp_hdr.op_code = OpCode::PUBKEY;
        resp_hdr.payload_len = sizeof(Payload_PubKey);
        memcpy(resp_hdr.sender_id, my_identity.node_id.c_str(), 16);

        vector<uint8_t> resp_load(sizeof(Payload_PubKey));
        memcpy(resp_load.data(), &pk_pkt, sizeof(Payload_PubKey));

        smart_send(sender_node_id, sender_ip, sender_port, resp_hdr, resp_load);
    }

    // --- [CLIENT] NHẬN KEY -> VERIFY LẠI ---
    else if (hdr.op_code == OpCode::PUBKEY) {
        if (payload.size() < sizeof(Payload_PubKey)) return;
        auto* pk_pkt = (Payload_PubKey*)payload.data();
        
        // Tìm session (cố gắng tìm mọi cách)
        Session* sess_ptr = nullptr;
        if (session_table.find(peer_key) != session_table.end()) sess_ptr = &session_table[peer_key];
        else {
             // Fallback tìm theo ID nếu đang relay
             string id_need = clean_id(hdr.sender_id, 16);
             for(auto& [k,s] : session_table) if(s.node_id == id_need) { sess_ptr = &s; break; }
        }

        if (!sess_ptr) return;
        Session& sess = *sess_ptr;

        // 1. Lưu Key
        sess.peer_falcon_pub = string((char*)pk_pkt->falcon_pub, 897);
        cout << "\n[NET] Da nhan Public Key. Verifying...\n";

        // 2. Verify chữ ký cũ
        if (sess.temp_signature.empty() || sess.handshake_data.empty()) return;
        bool is_valid = CryptoCore::falcon_verify(sess.peer_falcon_pub, sess.handshake_data, sess.temp_signature);
        
        if (!is_valid) {
            cout << "\n[SECURITY ALERT] CHU KY GIA MAO! Server fake!\n";
            session_table.erase(peer_key);
            return;
        }

        sess.node_id = clean_id(hdr.sender_id, 16);
        route_table.update_route(sess.node_id, sender_ip, sender_port, is_relay_mode);

        cout << "\n[SECURE] Chu ky hop le. Handshake hoan tat!\n";
        sess.is_established = true; 
        
        // [QUAN TRỌNG] BÁO HIỆU CHO NGƯỜI DÙNG BIẾT LÀ DÙNG ĐƯỢC RỒI
        cout << "\033[1;32m>>> READY! Ban co the chat hoac gui file ngay bay gio.\033[0m\n";
    }

    // 5. XỬ LÝ GÓI TIN MÃ HÓA (DATA PHASE)
    else if (hdr.flags & PacketFlag::ENCRYPTED) {
        if (session_table.find(peer_key) == session_table.end()) return;
        Session& sess = session_table[peer_key];

        // Tách Tag (16 bytes cuối)
        if (payload.size() < 16) return;
        string ciphertext((char*)payload.data(), payload.size() - 16);
        string tag((char*)payload.data() + payload.size() - 16, 16);
        string aad((char*)&hdr, sizeof(PacketHeader));
        string plaintext;

        // Giải mã
        if (CryptoCore::aes_gcm_decrypt(sess.aes_key, sess.aes_nonce, ciphertext, tag, aad, plaintext)) {
            // cout << "[DEBUG] Decrypted: " << plaintext << endl;
            
            // Parse JSON
            try {
                json j = json::parse(plaintext);
                
                // --- LOGIC XỬ LÝ LỆNH ---
                
                // A. Nhận lệnh LS REQUEST
                if (hdr.op_code == OpCode::FS_LIST_REQ) {
                    cout << "\n[CMD] " << peer_key << " muon xem danh sach file.\n";
                    json res = file_mgr.handle_ls();
                    send_secure_json(peer_key, OpCode::FS_LIST_RES, res);
                }
                
                // B. Nhận kết quả LS RESPONSE
                else if (hdr.op_code == OpCode::FS_LIST_RES) {
                    cout << "\n--- DANH SACH FILE TREN " << peer_key << " ---\n";
                    if (j.contains("files")) {
                        for (auto& f : j["files"]) {
                            cout << "+ " << f["n"] << " (" << f["s"] << " bytes)\n";
                        }
                    }
                    cout << "--------------------------------------\n" << flush;
                }

                // --- [SERVER] NHẬN YÊU CẦU META (Hỏi size) ---
                else if (hdr.op_code == OpCode::FS_META_REQ) {
                    string fname = j["n"];
                    long size = file_mgr.get_file_size(fname);
                    
                    cout << "\n[NET] Ben kia hoi file: " << fname << " (Size: " << size << ")\n";

                    json res;
                    res["n"] = fname;
                    res["s"] = size; // Trả về -1 nếu không tìm thấy
                    send_secure_json(peer_key, OpCode::FS_META_RES, res);
                }

                // --- [CLIENT] NHẬN PHẢN HỒI META (Biết size -> Bắt đầu tải Chunk 0) ---
                else if (hdr.op_code == OpCode::FS_META_RES) {
                    long size = j["s"];
                    if (size < 0) {
                        cout << "\n[ERR] File khong ton tai tren may doi phuong!\n";
                        dl_state.is_active = false;
                    } else {
                        cout << "\n[INFO] File size: " << size << " bytes. Bat dau tai...\n";
                        dl_state.total_size = size;
                        dl_state.current_offset = 0;

                        // Gửi Request xin Chunk đầu tiên (Offset 0, dài 1024 bytes)
                        json chunk_req;
                        chunk_req["n"] = dl_state.filename;
                        chunk_req["off"] = 0;
                        chunk_req["len"] = 1024; 
                        send_secure_json(peer_key, OpCode::FS_DATA_REQ, chunk_req);
                    }
                }

                // --- [SERVER] NHẬN YÊU CẦU DATA (Đọc file -> Gửi) ---
                else if (hdr.op_code == OpCode::FS_DATA_REQ) {
                    string fname = j["n"];
                    uint64_t off = j["off"];
                    size_t len = j["len"];

                    // Đọc từ ổ cứng
                    vector<uint8_t> data = file_mgr.read_file_chunk(fname, off, len);

                    // Gửi trả (Cần encode Base64 vì JSON không chứa được binary)
                    json res;
                    res["off"] = off;
                    res["d"] = CryptoCore::base64_encode_str(string(data.begin(), data.end()));
                    
                    send_secure_json(peer_key, OpCode::FS_DATA_RES, res);
                }

                // --- [CLIENT] NHẬN DATA (Ghi đĩa -> Xin tiếp) ---
                else if (hdr.op_code == OpCode::FS_DATA_RES) {
                    if (!dl_state.is_active) return; // Nếu user đã hủy tải thì bỏ qua

                    uint64_t off = j["off"];
                    string b64_data = j["d"];
                    
                    // Decode Base64 -> Binary
                    string raw_str = CryptoCore::base64_decode_str(b64_data);
                    vector<uint8_t> raw_data(raw_str.begin(), raw_str.end());

                    // Ghi xuống ổ cứng
                    file_mgr.write_file_chunk(dl_state.filename, off, raw_data);

                    // Cập nhật tiến độ
                    dl_state.current_offset += raw_data.size();

                    // Hiển thị % (Progress Bar)
                    int percent = (dl_state.current_offset * 100) / dl_state.total_size;
                    cout << "\n\r[DOWNLOADING] " << percent << "% (" 
                         << dl_state.current_offset << "/" << dl_state.total_size << ")" << flush;

                    // Kiểm tra xong chưa?
                    if (dl_state.current_offset >= dl_state.total_size) {
                        cout << "\n[SUCCESS] Tai xong! File luu tai: downloads/" << dl_state.filename << endl;
                        dl_state.is_active = false;
                    } else {
                        // CHƯA XONG -> XIN TIẾP CHUNK KẾ
                        json chunk_req;
                        chunk_req["n"] = dl_state.filename;
                        chunk_req["off"] = dl_state.current_offset;
                        chunk_req["len"] = 1024; // Xin tiếp 1KB
                        send_secure_json(peer_key, OpCode::FS_DATA_REQ, chunk_req);
                    }
                }

                else if (hdr.op_code == OpCode::FS_PUT_META_REQ) {
                    string fname = j["n"];
                    uint64_t fsize = j["s"];
                    
                    cout << "\n[NET] Peer muon Upload file: " << fname << " (" << fsize << " bytes).\n";
                    
                    // CHECK SECURITY POLICY
                    string error_msg = file_mgr.check_upload_policy(fname, fsize);
                    
                    json res;
                    if (error_msg.empty()) {
                        cout << "[SECURE] Policy Check PASSED. Chap nhan Upload.\n";
                        res["ok"] = true;
                    } else {
                        cout << "[SECURE] Policy Check FAILED: " << error_msg << endl;
                        res["ok"] = false;
                        res["msg"] = error_msg;
                    }
                    send_secure_json(peer_key, OpCode::FS_PUT_META_RES, res);
                }

                // --- [SENDER] NHẬN PHẢN HỒI UPLOAD (PUT_META_RES) ---
                else if (hdr.op_code == OpCode::FS_PUT_META_RES) {
                    bool ok = j["ok"];
                    if (!ok) {
                        string msg = j["msg"];
                        cout << "\n[ERR] Upload bi tu choi! Server noi: " << msg << endl;
                        up_state.is_uploading = false;
                    } else {
                        cout << "\n[INFO] Server chap nhan. Dang ban du lieu (UDP Blast)...\n";
                        
                        // VÒNG LẶP GỬI DỮ LIỆU (UDP FLOOD)
                        // Vì UDP không kết nối, ta cứ đọc và gửi liên tục.
                        // Để tránh nghẽn mạng, ta có thể sleep 1 chút xíu giữa các gói (optional)
                        
                        while (up_state.current_offset < up_state.total_size) {
                            // Đọc 1 chunk (1KB)
                            // Lưu ý: read_file_chunk lấy từ ROOT_DIR (folder shared của mình)
                            vector<uint8_t> chunk = file_mgr.read_file_chunk(up_state.filename, up_state.current_offset, 1024);
                            
                            if (chunk.empty()) break; // Hết file hoặc lỗi

                            // Gửi
                            json data_pkt;
                            data_pkt["n"] = up_state.filename;
                            data_pkt["off"] = up_state.current_offset;
                            data_pkt["d"] = CryptoCore::base64_encode_str(string(chunk.begin(), chunk.end()));
                            
                            send_secure_json(peer_key, OpCode::FS_PUT_DATA, data_pkt);

                            // Tăng offset
                            up_state.current_offset += chunk.size();
                            
                            // Hiển thị tiến độ (đơn giản)
                            if (up_state.current_offset % (100 * 1024) == 0) { // Cứ 100KB in 1 lần cho đỡ lag console
                                cout << "." << flush;
                            }
                        }
                        cout << "\n[SUCCESS] Da gui xong toan bo file!\n";
                        up_state.is_uploading = false;
                        print_prompt();
                    }
                }

                // --- [RECEIVER] NHẬN DỮ LIỆU UPLOAD (PUT_DATA) ---
                else if (hdr.op_code == OpCode::FS_PUT_DATA) {
                    string fname = j["n"];
                    uint64_t off = j["off"];
                    string b64 = j["d"];
                    
                    // Giải mã và ghi vào SHARED folder
                    string raw = CryptoCore::base64_decode_str(b64);
                    vector<uint8_t> data(raw.begin(), raw.end());
                    
                    // Dùng hàm write_upload_chunk (Ghi vào shared/)
                    file_mgr.write_upload_chunk(fname, off, data);
                    
                    // Không cần in log quá nhiều kẻo lag
                    // cout << "Recv chunk " << off << endl; 
                }
                
            } catch(...) {
                cout << "\n[ERR] Bad JSON format\n";
            }
        } else {
            cout << "\n[SECURITY ALERT] Giai ma that bai! Goi tin bi can thiep?\n";
        }
    }

    // --- [VAI TRÒ: MIDDLEMAN] NHẬN YÊU CẦU TÌM NGƯỜI ---
    else if (hdr.op_code == OpCode::P2P_FIND_NODE_REQ) {
        if (payload.size() < sizeof(Payload_FindNode)) return; // Chặn crash

        auto* req = (Payload_FindNode*)payload.data();
        string target_id = clean_id(req->target_id, 16);
        string requester_id = clean_id(hdr.sender_id, 16); // Thằng đi tìm (A)
        
        cout << "\n[P2P] Node " << requester_id.substr(0,8) << " nho tim: " << target_id << endl;
        
        Payload_NodeInfo res_info;
        memset(&res_info, 0, sizeof(res_info));
        bool found = false;
        string t_ip; int t_port;

        // --- BƯỚC 1: XÁC ĐỊNH THÔNG TIN ---
        // TH1: Tìm chính mình
        if (target_id == clean_id(my_identity.node_id.c_str(), 16)) {
            cout << "      -> DO LA TOI! Dang chuan bi phan hoi...\n";
            strncpy(res_info.target_id, my_identity.node_id.c_str(), 16);
            strncpy(res_info.ip, "0.0.0.0", INET_ADDRSTRLEN); 
            res_info.port = my_identity.port;
            found = true;
        }
        // TH2: Tìm hộ người khác
        else if (route_table.get_route(target_id, t_ip, t_port)) {
            cout << "      -> TOI BIET NO! Dang ship thong tin ho...\n";
            strncpy(res_info.target_id, target_id.c_str(), 16);
            strncpy(res_info.ip, t_ip.c_str(), INET_ADDRSTRLEN);
            res_info.port = t_port;
            found = true;

            // Kích hoạt đục lỗ (Chỉ cần khi Mode Live)
            if (!is_relay_mode) {
                Payload_NodeInfo assist_info;
                memset(&assist_info, 0, sizeof(assist_info));
                strncpy(assist_info.target_id, requester_id.c_str(), 16);
                strncpy(assist_info.ip, sender_ip, INET_ADDRSTRLEN);
                assist_info.port = sender_port;
                
                PacketHeader as_hdr; memset(&as_hdr, 0, sizeof(as_hdr)); memcpy(as_hdr.magic, "SM", 2);
                as_hdr.op_code = OpCode::P2P_ASSIST_REQ; as_hdr.payload_len = sizeof(Payload_NodeInfo);
                memcpy(as_hdr.sender_id, my_identity.node_id.c_str(), 16);
                vector<uint8_t> pl2(sizeof(Payload_NodeInfo)); memcpy(pl2.data(), &assist_info, sizeof(Payload_NodeInfo));
                net_engine.send_packet(as_hdr, pl2, t_ip, t_port); 
                cout << "      -> Da gui lenh HOLE PUNCH cho doi phuong.\n";
            }
        }

        // --- BƯỚC 2: GỬI KẾT QUẢ VỀ CHO THẰNG A ---
        if (found) {
            PacketHeader res_hdr; 
            memset(&res_hdr, 0, sizeof(res_hdr)); 
            memcpy(res_hdr.magic, "SM", 2);
            res_hdr.op_code = OpCode::P2P_FIND_NODE_RES; // 0x61
            res_hdr.payload_len = sizeof(Payload_NodeInfo);
            memcpy(res_hdr.sender_id, my_identity.node_id.c_str(), 16);

            vector<uint8_t> pl1(sizeof(Payload_NodeInfo)); 
            memcpy(pl1.data(), &res_info, sizeof(Payload_NodeInfo));

            // Luôn dùng smart_send để nó tự chọn Relay hoặc Direct
            smart_send(requester_id, sender_ip, sender_port, res_hdr, pl1);
            cout << "      => Da gui phan hoi 0x61 ve cho " << requester_id.substr(0,8) << endl;
        } else {
            cout << "      -> Rất tiếc, tôi cũng chịu!\n";
        }
    }
    // --- [VAI TRÒ: NGƯỜI ĐI TÌM (A)] NHẬN ĐƯỢC IP CỦA C ---
    else if (hdr.op_code == OpCode::P2P_FIND_NODE_RES) {
        auto* info = (Payload_NodeInfo*)payload.data();
        string t_ip = info->ip;
        int t_port = info->port;
        string t_id = clean_id(info->target_id, 16);
        vector<uint8_t> empty_payload;
        // NẾU IP LÀ 0.0.0.0 -> Lấy luôn IP của thằng vừa gửi gói này cho mình
        if (t_ip == "0.0.0.0") {
            t_ip = sender_ip; 
        }

        cout << "\n[P2P] Tim thay roi! " << t_id << " o tai " << t_ip << ":" << t_port << endl;
        cout << "[P2P] Dang thuc hien Hole Punching (Ket noi truc tiep)...\n";
        
        // Cập nhật Route luôn
        route_table.update_route(t_id, t_ip, t_port,is_relay_mode);

        if (is_relay_mode) {
            // Đang nhờ Admin ship -> Dùng ID cho chắc ăn (vì IP có thể là Admin)
            current_target = t_id; 
        } else {
            // Đang chạy Direct -> Dùng IP:Port cho trực quan
            current_target = t_ip + ":" + to_string(t_port);
        }

        PacketHeader hello_hdr; memset(&hello_hdr, 0, sizeof(hello_hdr)); memcpy(hello_hdr.magic, "SM", 2);
        hello_hdr.op_code = OpCode::WHO_ARE_YOU; 
        memcpy(hello_hdr.sender_id, my_identity.node_id.c_str(), 16);

        smart_send(t_id, t_ip, t_port, hello_hdr, empty_payload);
    }

    // --- [VAI TRÒ: MỤC TIÊU (C)] BỊ YÊU CẦU ĐẤM LỖ ---
    else if (hdr.op_code == OpCode::P2P_ASSIST_REQ) {
        auto* info = (Payload_NodeInfo*)payload.data();
        string a_ip = info->ip;      // IP thằng A
        int a_port = info->port;     // Port thằng A
        string a_id = clean_id(info->target_id, 16);

        cout << "\n[P2P] Dai Ca bao tin: Node " << a_id.substr(0,8) << " (" << a_ip << ") dang muon gap minh.\n";
        cout << "[P2P] Dang dam lo (Hole Punch) ve phia no...\n";

        // Gửi gói tin rác (P2P_HOLE_PUNCH) về phía A
        // Mục đích: Mở NAT của mình hướng về A, để lát nữa A gửi HELLO vào thì lọt qua được.
        PacketHeader punch_hdr; memset(&punch_hdr, 0, sizeof(punch_hdr)); memcpy(punch_hdr.magic, "SM", 2);
        punch_hdr.op_code = OpCode::P2P_HOLE_PUNCH; // Gói này bên kia nhận được thì vứt đi cũng được
        memcpy(punch_hdr.sender_id, my_identity.node_id.c_str(), 16);
        net_engine.send_packet(punch_hdr, {}, a_ip, a_port);
        vector<uint8_t> empty_payload;
        smart_send(a_id, a_ip, a_port, punch_hdr, empty_payload);
    }
    
    // --- [VAI TRÒ: A] NHẬN ĐƯỢC CÚ ĐẤM CỦA C ---
    else if (hdr.op_code == OpCode::P2P_HOLE_PUNCH) {
        // Nhận được cái này nghĩa là NAT đã thông!
        cout << "\n[P2P] <=== KET NOI THONG SUOT (NAT TRAVERSAL SUCCESS) ===>\n";
        // Bên kia đã chủ động liên lạc, giờ mình gửi lại WHO_ARE_YOU là ăn chắc 100%
        string peer_key = make_peer_key(sender);
        if (session_table.find(peer_key) == session_table.end() || !session_table[peer_key].is_established) {
             PacketHeader hello_hdr; memset(&hello_hdr, 0, sizeof(hello_hdr)); memcpy(hello_hdr.magic, "SM", 2);
             hello_hdr.op_code = OpCode::WHO_ARE_YOU; 
             memcpy(hello_hdr.sender_id, my_identity.node_id.c_str(), 16);
            
             vector<uint8_t> empty_payload;
            smart_send(hello_hdr.sender_id, sender_ip, sender_port, hello_hdr, empty_payload);
        }
    }

    // --- [VAI TRÒ: NGƯỜI NHẬN B] NHẬN HÀNG TỪ SHIPPER ---
    // --- [VAI TRÒ: NGƯỜI NHẬN B] NHẬN HÀNG TỪ SHIPPER ---
    else if (hdr.op_code == OpCode::RELAY_FWD) {

        try {
            // 1. Chuyển payload từ Admin thành chuỗi JSON
            string box_str((char * ) payload.data(), payload.size());
            json box = json::parse(box_str);

            // 2. Lấy dữ liệu Base64 và giải mã
            string b64_data = box["data"];
            string raw_data = CryptoCore::base64_decode_str(b64_data);

            if (raw_data.size() < sizeof(PacketHeader)) return;

            // 3. Tách Header gốc và Payload gốc

            PacketHeader inner_hdr;
            memcpy( & inner_hdr, raw_data.data(), sizeof(PacketHeader));
            vector < uint8_t > inner_payload;

            if (raw_data.size() > sizeof(PacketHeader)) {
                inner_payload.assign(raw_data.begin() + sizeof(PacketHeader), raw_data.end());
            }

            //cout << "\033[1;35m[RELAY]\033[0m Nhan goi tin \033[1;32m0x" << hex << (int) inner_hdr.op_code <<
            //"\033[0m tu \033[1;36m" << clean_id(inner_hdr.sender_id, 16).substr(0, 8) << "\033[0m qua Admin.\n";

            string real_sender_id = clean_id(inner_hdr.sender_id, 16);
            
            route_table.update_route(real_sender_id, sender_ip, sender_port, true);

            // 1. TÌM SESSION DỰA TRÊN "CĂN CƯỚC" (ID) - KHÔNG QUAN TÂM IP LÀ GÌ
            Session* target_session = nullptr;
            string session_key_in_map = "";

            for (auto & [key, sess]: session_table) {
                if (sess.node_id == real_sender_id) {
                    target_session = &sess;
                    session_key_in_map = key;
                    break;
                }
            }


            // 2. NẾU TÌM THẤY -> CẬP NHẬT ĐƯỜNG DẪN (ROAMING)
            // "À, thằng ID này giờ đang gửi qua đường Admin, mình cập nhật lại IP gửi về cho nó"
            if (target_session) {
                target_session->ip = sender_ip;     // IP Admin
                target_session->port = sender_port; // Port Admin
                
                // Mẹo cực hay: Để hàm send_secure_json tìm thấy session bằng IP Admin
                // Ta tạm thời map IP Admin vào chính Session này
                string admin_key = make_peer_key(sender);
                if (session_table.find(admin_key) == session_table.end()) {
                     // Chỉ trỏ con trỏ hoặc copy nhẹ, nhưng quan trọng là ta đã update IP trong sess gốc
                     session_table[admin_key] = *target_session; 
                } else {
                    // Nếu đã có entry Admin, cập nhật nội dung mới nhất từ sess gốc
                    session_table[admin_key] = *target_session;
                }
            }
            // --- CHIÊU THỨC "MƯỢN ĐƯỜNG" CỦA JUNA ---

            bool old_mode = is_relay_mode; // Lưu trạng thái hiện tại (có thể đang là false)
            is_relay_mode = true; // Ép mọi lệnh phản hồi (IAM, FS_LIST_RES...) đi qua Relay

            // 4. ĐỆ QUY: Xử lý gói tin bên trong

            // Ta dùng lại biến 'sender' (là IP/Port của Admin) để các hàm send_packet

            // biết đường gửi ngược lại cho Admin.

            handle_incoming_packet(inner_hdr, inner_payload, sender);

            // 4. ĐỒNG BỘ LẠI (QUAN TRỌNG NHẤT)
            // Sau khi xử lý xong (ví dụ Handshake thành công), session_table[admin_key] sẽ chứa Key mới.
            // Ta phải lưu Key đó ngược về cái session gốc tìm thấy ban đầu.
            if (!session_key_in_map.empty()) {
                string admin_key = make_peer_key(sender);
                if (session_table.find(admin_key) != session_table.end()) {
                    session_table[session_key_in_map] = session_table[admin_key];
                }
            }

            is_relay_mode = old_mode; // TRẢ LẠI TRẠNG THÁI (Cực kỳ quan trọng)

            // ----------------------------------------

        } catch (const exception & e) {

            cout << "[ERR] Loi boc vo Relay: " << e.what() << endl;

        }

    }

    // --- [VAI TRÒ: ADMIN / SUPERNODE] CHUYỂN TIẾP HÀNG ---
    else if (hdr.op_code == OpCode::RELAY_REQ) { // RELAY_REQ

        try {
            // 1. Giải mã JSON để biết gửi cho ai
            string box_str((char*)payload.data(), payload.size());
            json box = json::parse(box_str);

            string target_id = clean_id(box["target"].get<string>().c_str(), 16);
            string sender_id_clean = clean_id(hdr.sender_id, 16);
             
            route_table.update_route(sender_id_clean, sender_ip, sender_port,is_relay_mode); 
            // -------------------------------------------------------------

            cout << "[MIDDLEMAN] Dang ship hang tu " << clean_id(hdr.sender_id, 16).substr(0,8) 
                 << " -> toi " << target_id.substr(0,8) << endl;

            // 2. Tra cứu IP/Port của thằng đích (B)
            string b_ip; int b_port;
            if (route_table.get_route(target_id, b_ip, b_port)) {
                
                // 3. Đóng gói lại gửi đi (Chuyển thành RELAY_FWD)
                PacketHeader fwd_hdr = hdr; // Copy nguyên header cũ (giữ sender_id gốc)
                fwd_hdr.op_code = OpCode::RELAY_FWD;     // Đổi mã thành FORWARD (0x71)

                net_engine.send_packet(fwd_hdr, payload, b_ip, b_port);

                cout << "            => Ship thanh cong toi " << b_ip << ":" << b_port << endl;
            } else {
                cout << "            => [ERR] Khong tim thay thang " << target_id.substr(0,8) << " de ship!\n";
            }
        } catch (const exception& e) {
            cout << "[MIDDLEMAN ERR] " << e.what() << endl;
        }
    }
}


// --- XỬ LÝ LỆNH TỪ BÀN PHÍM ---
void handle_user_input() {
    string line;
    if (!getline(cin, line)) return;
    if (line.empty()) { print_prompt(); return; } 

    stringstream ss(line);
    string cmd;
    ss >> cmd;

    if (cmd == "exit") {
        cout << "Exiting Node...your node will off! Bye!\n";
        exit(0);
    }

    else if (cmd == "myid") {
        cout << "Your id: " << clean_id(my_identity.node_id.c_str(), 16) << "\n";
    }
    // thoat target
    else if (cmd == "quit") {
        if (current_target.empty()) {
             cout << "[INFO] You are not connected to anyone.\n";
        } else {
            cout << "\n[!] Disconnected with " << current_target << "!\n";
            
            // 1. Xóa session trong RAM (để lần sau phải handshake lại cho an toàn)
            // Cố gắng xóa cả Key theo IP và Key theo ID (nếu có)
            auto it = session_table.find(current_target);
            if (it != session_table.end()) session_table.erase(it);

            // 2. NẾU ĐANG LÀ RELAY -> DỌN RÁC (Giữ SuperNode, xóa IP ảo)
            if (is_relay_mode) {
                route_table.clean_temporary_nodes(); 
                
                // Mẹo: Reset biến mục tiêu về rỗng để tránh lỗi logic
                current_target = ""; 
            } else {
                current_target = ""; 
            }
        }
    }
    // --- LIST ---
    else if (cmd == "list") {
        cout << "\n--- LIST OF CONNECT ---\n";
        for (auto const& [key, sess] : session_table) {
            string status = sess.is_established ? "SECURE" : "Handshaking...";
            string marker = (key == current_target) ? "(*)" : "   ";
            cout << marker << " " << key << " | ID: " << sess.node_id
                 << "... | " << status << endl;
        }
    }
    else if (cmd == "mode") {
        string type; ss >> type;
        if (type == "help") {
            is_relay_mode = true;
            cout << "\033[1;33m[SYSTEM] Change to MODE HELP (Connect by Shipper Admin).\033[0m\n";
        } else {
            is_relay_mode = false;
            cout << "\033[1;32m[SYSTEM] Change to MODE LIVE (P2P).\033[0m\n";
        }
    }
    // --- USE ---
    else if (cmd == "use") {
        string target;
        ss >> target;
        if (target.empty()) {
            cout << "\nUSED: " << (current_target.empty() ? "none" : current_target) << endl;
        } else {
            current_target = target;
            cout << "\n[INFO] Target change to: " << current_target << endl;
        }
    }
    // --- CONNECT ---
    else if (cmd == "connect") {
        string ip; int port;
        if (ss >> ip >> port) {
            string target_key = ip + ":" + to_string(port);
            cout << "\n[CMD] Searching " << target_key << "...\n";
            current_target = target_key;

            PacketHeader hdr;
            memset(&hdr, 0, sizeof(hdr));
            memcpy(hdr.magic, "SM", 2);
            hdr.op_code = OpCode::WHO_ARE_YOU;
            hdr.payload_len = 0;
            memcpy(hdr.sender_id, my_identity.node_id.c_str(), 16);

            net_engine.send_packet(hdr, {}, ip, port);
        } else {
            cout << "\nHOW to: connect <ip> <port>\n";
        }
    }

    else if (cmd == "nodes") {
        route_table.print_routing_table();
    }

    // --- KẾT NỐI BẰNG ID (THÔNG MINH) ---
    else if (cmd == "id") {
        string target_id; ss >> target_id;
        if (target_id.empty()) {
            cout << "Use: id <NodeID>\n";
        } else {
            string ip; int port;
            bool is_direct_route = false; // <--- Biến chứa kết quả kiểm tra
            vector<uint8_t> empty_payload;

            bool found_in_cache = route_table.get_route(target_id, ip, port, is_direct_route);

            if (found_in_cache && !is_relay_mode && !is_direct_route) {
                cout << "\n[CACHE] Bo qua Route Relay (qua Admin) vi dang o Mode Live.\n";
                found_in_cache = false; 
            }

            // 1. Tìm trong danh bạ mình trước
            if (found_in_cache) {
                cout << "\n[ROUTE] Tim thay trong cache: " << ip << ":" << port << endl;
                // ... (Code kết nối cũ giữ nguyên) ...
                string target_key = ip + ":" + to_string(port);
                current_target = target_key;
                PacketHeader hdr; memset(&hdr, 0, sizeof(hdr)); memcpy(hdr.magic, "SM", 2);
                hdr.op_code = OpCode::WHO_ARE_YOU; memcpy(hdr.sender_id, my_identity.node_id.c_str(), 16);
                smart_send(target_id, ip, port, hdr, empty_payload);
            } 
            // 2. KHÔNG THẤY -> HỎI BOOTSTRAP (NHỜ VẢ)
            else {
                // Lấy thông tin Bootstrap (Node mồi)
                string bs_ip; int bs_port;
                if (route_table.get_bootstrap(bs_ip, bs_port)) {
                    cout << "\n[P2P] DON'T KNOW " << target_id << " WHERE. ASKING 'SHELL_server_1.0' (" << bs_ip << ")...\n";
                    
                    Payload_FindNode find_req;
                    memset(&find_req, 0, sizeof(find_req));
                    // Cắt chuỗi ID string vào char array an toàn
                    strncpy(find_req.target_id, target_id.c_str(), 16); 

                    PacketHeader hdr;
                    memset(&hdr, 0, sizeof(hdr));
                    memcpy(hdr.magic, "SM", 2);
                    hdr.op_code = OpCode::P2P_FIND_NODE_REQ; // <--- Gửi lệnh TÌM
                    hdr.payload_len = sizeof(Payload_FindNode);
                    memcpy(hdr.sender_id, my_identity.node_id.c_str(), 16);

                    vector<uint8_t> pl(sizeof(Payload_FindNode));
                    memcpy(pl.data(), &find_req, sizeof(Payload_FindNode));
                    
                    smart_send(target_id, bs_ip, bs_port, hdr, pl);
                } else {
                    cout << "\n[ERR] Can't found ID and no Bootstrap Node to ask!\n";
                }
            }
        }
    }
    // --- LS ---
    else if (cmd == "ls") {
        string target;
        ss >> target;
        if (target.empty()) target = current_target;

        if (target.empty()) {
            cout << "\n[ERR] No target choosen! Use command: 'connect' or 'use'\n";
        } else {
            cout << "\n[CMD] LS -> " << target << "...\n";
            send_secure_json(target, OpCode::FS_LIST_REQ, {});
        }
    }
    // --- GET (MỚI) ---
    else if (cmd == "get") {
        string fname;
        ss >> fname;
        string target = current_target;

        if (fname.empty() || target.empty()) {
            cout << "\nHOW to: get <filename> (NEED choose target first!)\n";
        } else {
            cout << "\n[CMD] ASK ABOUT SIZE '" << fname << "' from " << target << "...\n";
            
            // 1. Reset trạng thái download
            dl_state.filename = fname;
            dl_state.is_active = true;
            dl_state.peer_key = target;
            dl_state.current_offset = 0;

            // 2. Gửi gói tin META_REQ
            json req;
            req["n"] = fname;
            send_secure_json(target, OpCode::FS_META_REQ, req);
        }
    }
    else if (cmd == "put") {
        string fname;
        ss >> fname;
        string target = current_target;

        if (fname.empty() || target.empty()) {
            cout << "\nHOW to: put <local_filename> (NEED target!)\n";
        } else {
            // Kiểm tra file local có tồn tại không
            long fsize = file_mgr.get_file_size(fname); // Hàm này check trong Shared, cần sửa để check local? 
            // À, file_mgr đang trỏ vào ROOT_DIR. Để tiện, ta quy định:
            // MUỐN UP FILE THÌ PHẢI COPY FILE ĐÓ VÀO THƯ MỤC 'myshared' CỦA MÌNH TRƯỚC.
            
            if (fsize < 0) {
                cout << "\n[ERR] File '" << fname << "' not found in your 'shared' folder!\n";
                cout << "Please copy file to 'shellmap/shared/' first.\n";
            } else {
                cout << "\n[CMD] Requesting upload '" << fname << "' (" << fsize << " bytes) to " << target << "...\n";
                
                // Set state
                up_state.filename = fname;
                up_state.total_size = fsize;
                up_state.current_offset = 0;
                up_state.is_uploading = true;
                up_state.peer_key = target;

                // Gửi Request xin phép
                json req;
                req["n"] = fname;
                req["s"] = fsize;
                send_secure_json(target, OpCode::FS_PUT_META_REQ, req);
            }
        }
    }
    else if (cmd == "me") {
        cout << "\n[SYSTEM] OPENING Local Shell in Downloads folder...\n";
        cout << "(Press 'exit' to return ShellMap)\n";
        
        // 1. Lưu vị trí hiện tại để lát quay về
        auto old_path = fs::current_path();
        
        // 2. Nhảy vào thư mục Downloads
        try {
            // file_mgr.get_download_path() trả về đường dẫn shellmap/downloads/
            fs::current_path("shellmap/downloads"); 
            
            // 3. Gọi Shell thật của Linux
            // Lệnh này sẽ PAUSE ShellMap lại cho đến khi bạn thoát bash
            int ret = system("/bin/bash"); 
            (void)ret; // Fix warning unused variable
            
        } catch (const exception& e) {
            cout << "\n[ERR] Can't open shell: " << e.what() << endl;
        }

        // 4. Quay lại vị trí cũ sau khi User thoát Shell
        fs::current_path(old_path);
        cout << "\n[SYSTEM] Welcome back ShellMap!\n";
    }

    else if (cmd == "config") {
        string subcmd;
        ss >> subcmd;

        if (subcmd == "status" || subcmd.empty()) {
            // Xem trạng thái: config status
            cout << file_mgr.get_config_status();
        }
        else if (subcmd == "upload") {
            // Bật tắt upload: config upload on/off
            string val;
            ss >> val;
            if (val == "on") {
                file_mgr.set_upload_allow(true);
                cout << "[CONFIG] Upload has been ENABLED (Others can put files).\n";
            } else if (val == "off") {
                file_mgr.set_upload_allow(false);
                cout << "[CONFIG] Upload has been DISABLED (Secure mode).\n";
            } else {
                cout << "Use: config upload <on/off>\n";
            }
        }
        else if (subcmd == "size") {
            // Chỉnh kích thước: config size 100 (MB)
            int mb;
            if (ss >> mb) {
                file_mgr.set_max_size_mb(mb);
                cout << "[CONFIG] Max upload size set to: " << mb << " MB.\n";
            } else {
                cout << "Use: config size <mb_number> (Ex: config size 50)\n";
            }
        }
        else {
            cout << "Unknown config. Try: config + status, upload, size\n";
        }
    }

    else if (cmd == "myshared") {
        cout << "\n[SYSTEM] OPENING Local Shell in SHARED folder...\n";
        cout << "(Press 'exit' to return ShellMap)\n";
        
        // 1. Lưu vị trí cũ
        auto old_path = fs::current_path();
        
        // 2. Nhảy vào thư mục Shared
        try {
            // Kiểm tra xem thư mục có tồn tại không cho chắc
            if (fs::exists("shellmap/shared")) {
                fs::current_path("shellmap/shared"); 
                
                // 3. Gọi Shell
                int ret = system("/bin/bash"); 
                (void)ret; 
            } else {
                cout << "\n[ERR] Folder 'shellmap/shared' not exist!\n";
            }
            
        } catch (const exception& e) {
            cout << "\n[ERR] Can't open shell: " << e.what() << endl;
        }

        // 4. Quay về
        fs::current_path(old_path);
        cout << "\n[SYSTEM] Welcome back ShellMap!\n";
    }
    // --- ELSE ---
    else {
        cout << "\nNot found command! Checking: connect, id , list, use, ls, get, exit\n";
    }
    
    print_prompt(); 
}

int main() {
    // 1. Init
    NodeInitializer node_init;
    node_init.run();
    // ÉP VỀ 16 KÝ TỰ NGAY TẠI ĐÂY
    if (node_init.context.node_id.length() > 16) {
        node_init.context.node_id = node_init.context.node_id.substr(0, 16);
    }
    my_identity = node_init.context;

    // --- [MỚI] UPnP AUTO CONFIG ---
    UPnPHelper upnp;
    
    // --- VÒNG LẶP CHỌN PORT (PORT HUNTING) ---
    while (true) {
        cout << "\n--- NETWORK SETUP (Port: " << my_identity.port << ") ---\n";

        // 1. Thử Init Socket nội bộ (Kiểm tra xem máy mình có đang chạy ShellMap khác không)
        if (!net_engine.init(my_identity.port)) {
            cout << "[ERR] Port " << my_identity.port << " dang bi chiem boi tien trinh khac tren may nay!\n";
            cout << ">> Nhap Port khac (VD: 5557): ";
            cin >> my_identity.port;
            continue; // Thử lại
        }

        // 2. Thử UPnP (Kiểm tra xem máy khác trong Wifi có chiếm không)
        int upnp_status = upnp.try_map_port(my_identity.port);
        
        if (upnp_status == 0) {
            // Hiển thị cả 2 IP cho Juna dễ chọn
            cout << "\n>>> NETWORK INFO:\n";
            cout << "    [LAN IP]    \033[1;33m" << upnp.local_ip << "\033[0m : " << my_identity.port << " (Use for Local/Wifi)\n";
            cout << "    [PUBLIC IP] \033[1;32m" << upnp.public_ip << "\033[0m : " << my_identity.port << " (Use for Internet)\n";
            
            // Cảnh báo nếu IP Public bị trùng dải Private (Double NAT)
            if (upnp.public_ip.find("192.168.") == 0 || upnp.public_ip.find("10.") == 0) {
                 cout << "    [WARN] Public IP looks like Private. Double NAT detected!\n";
            }
            break;
        }
        else if (upnp_status == 2) {
            // Bị trùng trên Router
            cout << "[!] Port nay da co nguoi dung tren Router!\n";
            cout << "Ban muon doi Port khong? (Nhap so Port moi hoac 0 de giu nguyen chay LAN only): ";
            int new_port;
            cin >> new_port;
            
            if (new_port > 0) {
                my_identity.port = new_port;
                net_engine.close_socket(); // Đóng socket cũ để bind socket mới
                continue; // Lặp lại vòng check
            } else {
                cout << ">>> Chap nhan chay LAN Only (Khong ra Internet duoc).\n";
                break;
            }
        } 
        else {
            // Lỗi Router không hỗ trợ UPnP -> Chấp nhận chạy LAN
            cout << ">>> Router khong ho tro UPnP. Chay LAN Only.\n";
            break;
        }
    }
    
    // Cập nhật lại ID vào NodeContext (để đảm bảo đồng bộ)
    node_init.context.port = my_identity.port;
    
    my_identity.is_admin = route_table.check_my_role(my_identity.node_id);

    if (!my_identity.is_admin) {
        auto super_nodes = route_table.get_all_supernodes();
        if (super_nodes.empty()) {
            cout << "[WARN] Can't find SuperNode in nodes.json!\n";
        }
        for (auto& sn : super_nodes) {
            // Giả sử sn lúc này là một struct hoặc pair có chứa ID
            // Nếu sn chỉ có {IP, Port}, bạn nên sửa hàm get_all_supernodes trả về ID nữa.
            
            cout << "[SYSTEM] Pinging SuperNode " << sn.ip << ":" << sn.port << " to register...\n";
            
            PacketHeader ping_hdr; 
            memset(&ping_hdr, 0, sizeof(ping_hdr)); 
            memcpy(ping_hdr.magic, "SM", 2);
            ping_hdr.op_code = OpCode::PING; // Dùng OpCode PING
            memcpy(ping_hdr.sender_id, my_identity.node_id.c_str(), 16);
            ping_hdr.payload_len = 0; // Ping không cần nội dung

            // Gửi thẳng (Direct) vì đây là bootstrap
            net_engine.send_packet(ping_hdr, {}, sn.ip, sn.port);
        }
    }

    cout << "\n=== SHELLMAP CLI ===\n";
    cout << "Your ID: " << clean_id(my_identity.node_id.c_str(), 16) << "\n";
    cout << "Press 'connect <ip> <port>' to connect other node.\n";
    print_prompt();

    // 2. VÒNG LẶP SỰ KIỆN (Event Loop) dùng select()
    int sockfd = net_engine.get_socket_fd();
    
    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);      // Lắng nghe Mạng
        FD_SET(STDIN_FILENO, &readfds); // Lắng nghe Bàn phím

        // Timeout 100ms để vòng lặp không bị treo cứng
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        int activity = select(max(sockfd, STDIN_FILENO) + 1, &readfds, NULL, NULL, &tv);

        if (activity > 0) {
            // A. CÓ DỮ LIỆU TỪ MẠNG
            if (FD_ISSET(sockfd, &readfds)) {
                PacketHeader hdr;
                vector<uint8_t> payload;
                sockaddr_in sender;
                if (net_engine.recv_packet(hdr, payload, sender) > 0) {
                    handle_incoming_packet(hdr, payload, sender);
                    // In lại dấu nhắc nếu đang chat dở
                    print_prompt();
                }
            }

            // B. CÓ DỮ LIỆU TỪ BÀN PHÍM
            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                handle_user_input();
            }
        }
    }

    return 0;
}