#include "VerificationManager.hpp"
#include <iostream>
#include <cstring>

uint64_t VerificationManager::initiate_verification(
    const std::string& node_id,
    const std::string& declared_ip,
    uint16_t declared_port
) {
    auto req = std::make_shared<VerificationRequest>();
    req->node_id = node_id;
    req->declared_ip = declared_ip;
    req->declared_port = declared_port;
    req->probe_id = next_probe_id_++;
    req->state = VerificationState::PENDING;
    
    // TODO: Generate proper checksum
    req->probe_checksum = 0;
    
    verifications_[node_id] = req;
    return req->probe_id;
}

bool VerificationManager::handle_probe_ack(
    const std::string& node_id,
    uint64_t probe_id,
    uint32_t checksum
) {
    auto it = verifications_.find(node_id);
    if (it == verifications_.end()) return false;

    auto req = it->second;
    if (req->probe_id != probe_id) return false;
    if (req->probe_checksum != checksum) return false;

    req->state = VerificationState::VERIFIED;
    req->is_server = true;
    return true;
}

VerificationManager::VerificationState VerificationManager::get_verification_state(const std::string& node_id) {
    auto it = verifications_.find(node_id);
    if (it == verifications_.end()) return VerificationState::PENDING;
    return it->second->state;
}

bool VerificationManager::is_server(const std::string& node_id) {
    auto it = verifications_.find(node_id);
    if (it == verifications_.end()) return false;
    return it->second->is_server;
}

void VerificationManager::cleanup_expired_verifications(uint64_t timeout_ms) {
    // TODO: Implement timeout logic
}

std::map<std::string, std::shared_ptr<VerificationManager::VerificationRequest>> 
VerificationManager::get_pending_verifications() {
    return verifications_;
}

std::pair<uint64_t, uint32_t> VerificationManager::generate_probe_credentials() {
    uint64_t probe_id = next_probe_id_++;
    // TODO: Generate proper checksum
    uint32_t checksum = 0;
    return {probe_id, checksum};
}
