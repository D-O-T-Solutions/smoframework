#include "SessionManager.hpp"
#include <iostream>
#include <chrono>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

// Helper to convert bytes to hex string for logging (works with both string and vector)
static std::string bytes_to_hex_short(const std::string& bytes, size_t len = 16) {
    std::stringstream ss;
    for (size_t i = 0; i < std::min(len, bytes.size()); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)bytes[i];
    }
    return ss.str();
}

static std::string bytes_to_hex_short_vec(const std::vector<uint8_t>& bytes, size_t len = 16) {
    std::stringstream ss;
    for (size_t i = 0; i < std::min(len, bytes.size()); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    return ss.str();
}

std::shared_ptr<SessionManager::Session> SessionManager::get_or_create_session(const std::string& node_id) {
    auto it = sessions_.find(node_id);
    if (it != sessions_.end()) {
        return it->second;
    }

    // Create new session
    auto session = std::make_shared<Session>();
    session->node_id = node_id;
    session->state = SessionState::NONE;
    session->created_time = std::chrono::system_clock::now().time_since_epoch().count();
    session->last_activity = session->created_time;
    // Initialize counters
    session->crypto_nonce_counter = 0;
    session->packet_nonce_counter = 0;

    sessions_[node_id] = session;
    return session;
}

std::shared_ptr<SessionManager::Session> SessionManager::get_session(const std::string& node_id) {
    auto it = sessions_.find(node_id);
    if (it != sessions_.end()) {
        return it->second;
    }
    return nullptr;
}

void SessionManager::destroy_session(const std::string& node_id) {
    sessions_.erase(node_id);
}

void SessionManager::set_handshake_state(
    const std::string& node_id,
    const std::string& kyber_ss,
    const std::string& ecdh_priv
) {
    auto session = get_or_create_session(node_id);
    // Only set temp_kyber_ss_initiator if it's not already set (from a previous WELCOME)
    if (session->temp_kyber_ss_initiator.empty() && !kyber_ss.empty()) {
        session->temp_kyber_ss_initiator = kyber_ss;  // When we initiate, we'll decaps the peer's CT
    }
    // Only set ecdh_priv if not already set
    if (session->temp_ecdh_priv.empty()) {
        session->temp_ecdh_priv = ecdh_priv;
    }
    // Only set state to INITIATED if not already in progress
    if (session->state == SessionState::NONE) {
        session->state = SessionState::INITIATED;
    }
}

void SessionManager::set_peer_ecdh(const std::string& node_id, const std::string& ecdh_pub) {
    auto session = get_session(node_id);
    if (!session) {
        session = get_or_create_session(node_id);
    }
    session->temp_ecdh_peer_pub = ecdh_pub;
    // Don't set HANDSHAKING state anymore - it's no longer needed
}

bool SessionManager::establish_session(const std::string& node_id) {
      // std::cerr << "[SESSION] DEBUG: establish_session called for " << node_id << std::endl;
     auto session = get_session(node_id);
     if (!session) {
         std::cerr << "[SESSION] Session not found!" << std::endl;
         return false;
     }

      if ((session->temp_kyber_ss_responder.empty() && session->temp_kyber_ss_initiator.empty()) ||
          session->temp_ecdh_peer_pub.empty() || session->temp_ecdh_priv.empty()) {
          std::cerr << "[SESSION] Missing handshake state for " << node_id << std::endl;
          return false;
      }

      // Calculate ECDH shared secret - use stored one if available, otherwise compute
      std::string ecdh_ss;
      if (!session->temp_ecdh_ss.empty()) {
          // Use previously computed ECDH_SS (from initiator's handle_welcome)
          ecdh_ss = session->temp_ecdh_ss;
          // std::cout << "[DEBUG-ESTABLISH] Using stored ECDH_SS from initiator" << std::endl;
      } else {
          // Compute ECDH_SS (fallback for responder-only handshakes)
          // std::cout << "[DEBUG-ESTABLISH] ECDH inputs for node " << node_id << ":" << std::endl;
          std::cout << "  Our priv:    " << bytes_to_hex_short(session->temp_ecdh_priv) << "... (len=" << session->temp_ecdh_priv.size() << ")" << std::endl;
          std::cout << "  Peer pub:    " << bytes_to_hex_short(session->temp_ecdh_peer_pub) << "..." << std::endl;
          if (!CryptoCore::compute_x25519_secret(session->temp_ecdh_priv, session->temp_ecdh_peer_pub, ecdh_ss)) {
              std::cerr << "[SESSION] Failed to compute X25519 shared secret for " << node_id << std::endl;
              return false;
          }
      }
     
      // Combine both Kyber shared secrets in a canonical order
      // CRITICAL: Use lexicographic ordering to ensure both nodes get the SAME combined SS
      // In bidirectional handshakes, responder and initiator labels are role-dependent,
      // so we sort them to get a deterministic combination
      std::string combined_kyber_ss;
      if (!session->temp_kyber_ss_responder.empty() && !session->temp_kyber_ss_initiator.empty()) {
          // Both available - sort them lexicographically for deterministic ordering
          if (session->temp_kyber_ss_responder < session->temp_kyber_ss_initiator) {
              combined_kyber_ss = session->temp_kyber_ss_responder + session->temp_kyber_ss_initiator;
          } else {
              combined_kyber_ss = session->temp_kyber_ss_initiator + session->temp_kyber_ss_responder;
          }
      } else {
          // Only one available - use it
          combined_kyber_ss = session->temp_kyber_ss_responder.empty() ? 
                              session->temp_kyber_ss_initiator : 
                              session->temp_kyber_ss_responder;
      }
       
       // std::cout << "[DEBUG-ESTABLISH] For node " << node_id << ":" << std::endl;
       // std::cout << "  Kyber SS (Responder): " << bytes_to_hex_short(session->temp_kyber_ss_responder) << std::endl;
       // std::cout << "  Kyber SS (Initiator): " << bytes_to_hex_short(session->temp_kyber_ss_initiator) << std::endl;
       // std::cout << "  ECDH SS:  " << bytes_to_hex_short(ecdh_ss) << std::endl;
      
       kdf_derive_keys(combined_kyber_ss, ecdh_ss, session->aes_key, session->aes_iv);
       
       // std::cout << "[DEBUG-ESTABLISH] Derived keys for node " << node_id << ":" << std::endl;
       // std::cout << "  AES Key: " << bytes_to_hex_short_vec(session->aes_key) << "... (len=" << session->aes_key.size() << ")" << std::endl;
       // std::cout << "  AES IV:  " << bytes_to_hex_short_vec(session->aes_iv) << " (len=" << session->aes_iv.size() << ")" << std::endl;

      session->state = SessionState::ESTABLISHED;
      session->last_activity = std::chrono::system_clock::now().time_since_epoch().count();

     // std::cout << "[SESSION] Session established for " << node_id << std::endl;
     return true;
 }

std::vector<uint8_t> SessionManager::encrypt_message(
     const std::string& node_id,
     const std::vector<uint8_t>& plaintext,
     uint64_t packet_nonce
 ) {
     auto session = get_session(node_id);
     if (!session || session->state != SessionState::ESTABLISHED) {
         std::cerr << "[SESSION] Session not established for " << node_id << std::endl;
         return {};
     }

      // Derive nonce deterministically from packet_nonce instead of using separate counter
      std::vector<uint8_t> nonce = derive_nonce_from_packet_nonce(packet_nonce);

     // Prepare key and nonce strings for CryptoCore
     std::string key_str((char*)session->aes_key.data(), session->aes_key.size());
     std::string nonce_str((char*)nonce.data(), nonce.size());
     std::string plaintext_str((char*)plaintext.data(), plaintext.size());
     std::string aad = "";  // No additional authenticated data for now

     // Encrypt using AES-256-GCM
     std::string ciphertext_str, tag_str;
     if (!CryptoCore::aes_gcm_encrypt(key_str, nonce_str, plaintext_str, aad, ciphertext_str, tag_str)) {
         std::cerr << "[SESSION] AES-256-GCM encryption failed for " << node_id << std::endl;
         return {};
     }

     // Combine ciphertext + tag (tag is last 16 bytes)
     std::vector<uint8_t> result;
     result.insert(result.end(), ciphertext_str.begin(), ciphertext_str.end());
     result.insert(result.end(), tag_str.begin(), tag_str.end());

     session->last_activity = std::chrono::system_clock::now().time_since_epoch().count();
     return result;
 }

std::vector<uint8_t> SessionManager::decrypt_message(
      const std::string& node_id,
      const std::vector<uint8_t>& ciphertext_with_tag,
      uint64_t packet_nonce
  ) {
      auto session = get_session(node_id);
      if (!session || session->state != SessionState::ESTABLISHED) {
          std::cerr << "[SESSION] Session not established for " << node_id << std::endl;
          return {};
      }

      // GCM tag is last 16 bytes
      if (ciphertext_with_tag.size() < 16) {
          std::cerr << "[SESSION] Invalid ciphertext size (too small for tag)" << std::endl;
          return {};
      }

      size_t ct_len = ciphertext_with_tag.size() - 16;
      std::vector<uint8_t> ciphertext_only(ciphertext_with_tag.begin(), ciphertext_with_tag.begin() + ct_len);
      std::vector<uint8_t> tag(ciphertext_with_tag.end() - 16, ciphertext_with_tag.end());

       // Derive nonce deterministically from packet_nonce instead of using separate counter
       std::vector<uint8_t> nonce = derive_nonce_from_packet_nonce(packet_nonce);

      // Prepare strings for CryptoCore
      std::string key_str((char*)session->aes_key.data(), session->aes_key.size());
      std::string nonce_str((char*)nonce.data(), nonce.size());
      std::string ciphertext_str((char*)ciphertext_only.data(), ciphertext_only.size());
      std::string tag_str((char*)tag.data(), tag.size());
      std::string aad = "";

      // Decrypt using AES-256-GCM
      std::string plaintext_str;
      if (!CryptoCore::aes_gcm_decrypt(key_str, nonce_str, ciphertext_str, tag_str, aad, plaintext_str)) {
          std::cerr << "[SESSION] AES-256-GCM decryption failed for " << node_id << std::endl;
          return {};
      }

      std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());
      session->last_activity = std::chrono::system_clock::now().time_since_epoch().count();
      return plaintext;
  }

bool SessionManager::is_session_active(const std::string& node_id) {
    auto session = get_session(node_id);
    if (!session) return false;
    return session->state == SessionState::ESTABLISHED;
}

std::map<std::string, std::shared_ptr<SessionManager::Session>> SessionManager::get_all_sessions() {
    return sessions_;
}

void SessionManager::cleanup_expired_sessions(uint64_t timeout_ms) {
    uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();
    std::vector<std::string> to_remove;
    
    // Convert timeout_ms to nanoseconds for consistency
    uint64_t timeout_ns = timeout_ms * 1000000;
    // Handshake timeout: 5 seconds = 5000000000 nanoseconds
    uint64_t handshake_timeout_ns = 5000000000ULL;

    for (auto& [node_id, session] : sessions_) {
        // Check for handshake timeout (5 seconds max for INITIATED, WELCOME_RECEIVED, WELCOME_SENT states)
        if ((session->state == SessionState::INITIATED || 
             session->state == SessionState::WELCOME_RECEIVED ||
             session->state == SessionState::WELCOME_SENT) &&
            (now - session->created_time) > handshake_timeout_ns) {
            // std::cout << "[SESSION] Handshake timeout for " << node_id << std::endl;
            to_remove.push_back(node_id);
            continue;
        }
        
        // Check for general activity timeout
        if ((now - session->last_activity) > timeout_ns) {
            to_remove.push_back(node_id);
        }
    }

    for (const auto& node_id : to_remove) {
        // std::cout << "[SESSION] Cleaning up expired session: " << node_id << std::endl;
        sessions_.erase(node_id);
    }
}

void SessionManager::kdf_derive_keys(
     const std::string& kyber_ss,
     const std::string& ecdh_ss,
     std::vector<uint8_t>& out_key,
     std::vector<uint8_t>& out_iv
 ) {
     // Use CryptoCore::derive_hybrid_key to derive AES-256 key + nonce from Kyber SS + ECDH SS
     std::string aes_key_str, nonce_str;
     if (!CryptoCore::derive_hybrid_key(kyber_ss, ecdh_ss, aes_key_str, nonce_str)) {
         std::cerr << "[SESSION] KDF failed" << std::endl;
         return;
     }

     // Copy to output vectors
     out_key.assign(aes_key_str.begin(), aes_key_str.end());
     out_iv.assign(nonce_str.begin(), nonce_str.end());
 }

std::vector<uint8_t> SessionManager::derive_nonce_from_packet_nonce(uint64_t packet_nonce) {
    // Derive 12-byte GCM nonce deterministically from 64-bit packet_nonce
    // Format: [8 bytes: packet_nonce in little-endian][4 bytes: zeros for GCM format]
    std::vector<uint8_t> nonce(12, 0);
    
    // Put packet_nonce in first 8 bytes (little-endian)
    for (int i = 0; i < 8; i++) {
        nonce[i] = (uint8_t)((packet_nonce >> (i * 8)) & 0xFF);
    }
    
    // Last 4 bytes remain zero (standard GCM nonce padding)
    return nonce;
}

std::vector<uint8_t> SessionManager::generate_next_nonce(uint64_t& counter) {
     // For GCM mode, use 12-byte nonce
     // Use counter-based approach: increment and convert to nonce
     counter++;
     
     std::vector<uint8_t> nonce(12, 0);
     
      // Put counter in first 8 bytes (little-endian)
      uint64_t counter_ne = counter;
      for (int i = 0; i < 8 && counter_ne > 0; i++) {
          nonce[i] = (uint8_t)(counter_ne & 0xFF);
          counter_ne >>= 8;
      }
      
      return nonce;
  }

bool SessionManager::migrate_session(const std::string& placeholder_id, const std::string& real_id) {
    // std::cout << "[SESSION] Migrating session from placeholder " << placeholder_id 
//               << " to real ID " << real_id << std::endl;
    
    auto placeholder_session = get_session(placeholder_id);
    if (!placeholder_session) {
        std::cerr << "[SESSION] Placeholder session not found: " << placeholder_id << std::endl;
        return false;
    }
    
    // std::cout << "[SESSION] Found placeholder session, ptr=" << (void*)placeholder_session.get() << std::endl;
    
    // Check if a session with real_id already exists
    auto real_session = get_session(real_id);
    if (real_session) {
        // Session already exists with real ID (probably from receiving HELLO before WELCOME)
        // Just discard the placeholder and use the existing one
        // std::cout << "[SESSION] Session already exists for real ID: " << real_id 
//                   << ", discarding placeholder" << std::endl;
        sessions_.erase(placeholder_id);
        return true;
    }
    
    // Move the placeholder session to the real ID
    placeholder_session->node_id = real_id;
    
    // FIRST: Erase the placeholder entry
    auto it = sessions_.find(placeholder_id);
    // std::cout << "[SESSION] Looking for placeholder_id=" << placeholder_id.substr(0, 8) << "... in map" << std::endl;
    // std::cout << "[SESSION] Found? " << (it != sessions_.end() ? "YES" : "NO") << std::endl;
    // std::cout << "[SESSION] Before erase, sessions size=" << sessions_.size() << std::endl;
    if (it != sessions_.end()) {
        // std::cout << "[SESSION] Erasing entry with key=" << it->first.substr(0, 8) << "..." << std::endl;
        sessions_.erase(it);
    }
    
    // THEN: Add with the real ID
    sessions_[real_id] = placeholder_session;
    // std::cout << "[SESSION] Added session with key=" << real_id.substr(0, 8) << "... to map" << std::endl;
    // std::cout << "[SESSION] Sessions map now has " << sessions_.size() << " entries after add" << std::endl;
    
    // Debug: print all session keys AFTER reregister
    for (const auto& [key, session] : sessions_) {
        // std::cout << "[SESSION]   Final - Key: " << key.substr(0, 8) << "..., Session ID: " << session->node_id.substr(0, 8) << "..., ptr=" << (void*)session.get() << std::endl;
    }
    
    // Verify migration by trying to get the new session
    auto migrated = get_session(real_id);
    // std::cout << "[SESSION] After migration, get_session(" << real_id.substr(0, 8) << "...) returns ptr=" << (void*)migrated.get() << std::endl;
    
    // std::cout << "[SESSION] Session migrated successfully to real ID: " << real_id << std::endl;
    return true;
}

std::pair<std::string, std::shared_ptr<SessionManager::Session>> SessionManager::find_placeholder_session() {
    // Look for any INITIATED session with map key that's all zeros (placeholder)
    // Note: The map KEY (node_id in sessions_ map) should be all zeros, not necessarily the Session->node_id
    for (auto& [node_id_key, session] : sessions_) {
        // Check if map key is all zeros (placeholder)
        bool is_placeholder = true;
        for (char c : node_id_key) {
            if (c != '0') {
                is_placeholder = false;
                break;
            }
        }
        
        // Found a placeholder session in INITIATED state
        if (is_placeholder && session->state == SessionState::INITIATED) {
            // std::cout << "[SESSION] Found placeholder session in INITIATED state" << std::endl;
            return {node_id_key, session};  // Return both the map key and the session
        }
    }
    
    return {"", nullptr};  // Return empty key and null pointer if not found
}
