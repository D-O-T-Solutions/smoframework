#pragma once

#include "bootstrap_protocol.hpp"
#include "core/network/packet_dispatcher.hpp"
#include "core/mesh/mesh_manager.hpp"
#include "core/authority/authority.hpp"
#include "core/governance/governance.hpp"
#include "core/recovery/crl.hpp"
#include "core/mesh/mesh_fsm.hpp"

namespace smo::bootstrap {

inline void register_bootstrap_handler_inline(network::PacketDispatcher& dispatcher, MeshManager& mesh_mgr,
                                    authority::MeshAuthority& authority, GovernanceEngine* governance,
                                    recovery::CRL* crl, network::hl::Transport* transport,
                                    mesh::MeshFsm* mesh_fsm = nullptr)
{
    dispatcher.register_handler(kOpcodeBootstrapRequest,
                                [&mesh_mgr, &authority, governance, crl, mesh_fsm](Packet&& pkt, const smo::Endpoint& remote,
                                                                                     network::hl::Transport& t) -> Result<void> {
                                    (void)remote;
                                    auto req = BootstrapRequest::decode_cbor(pkt.payload);
                                    if (!req)
                                        return req.error();

                                    auto resp =
                                        handle_bootstrap_request(req.value(), mesh_mgr, authority, governance, crl, mesh_fsm);
                                    if (!resp)
                                        return resp.error();

                                    auto resp_bytes = resp.value().encode_cbor();

                                    Packet resp_pkt;
                                    resp_pkt.header.protocol_version = kPacketProtocolVersion;
                                    resp_pkt.opcode_id = kOpcodeBootstrapResponse;
                                    resp_pkt.session_id() = pkt.session_id();
                                    resp_pkt.intent_id = pkt.intent_id;
                                    resp_pkt.timestamp() = pkt.timestamp();
                                    resp_pkt.header.nonce = pkt.header.nonce;
                                    resp_pkt.payload = std::move(resp_bytes);

                                    std::error_code ec = t.send(std::move(resp_pkt), static_cast<const network::hl::Endpoint&>(remote));
                                    if (ec)
                                    {
                                        return SMO_ERR_TRANSPORT(static_cast<int>(ec.value()), Error, RetrySafe,
                                                                 None, "Failed to send bootstrap response");
                                    }
                                    return {};
                                });

    (void)transport;
}

} // namespace smo::bootstrap
