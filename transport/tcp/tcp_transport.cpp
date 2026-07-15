#include "tcp_transport.h"

namespace smo {

struct TcpTransport::Impl {};

TcpTransport::TcpTransport() noexcept = default;
TcpTransport::~TcpTransport() noexcept = default;

std::error_code TcpTransport::listen(const Endpoint& ep,
                                     PacketHandler on_packet,
                                     ErrorHandler on_error) {
    (void)ep; (void)on_packet; (void)on_error;
    return make_error_code(Errc::NOT_IMPLEMENTED);
}

std::error_code TcpTransport::connect(const Endpoint& remote) {
    (void)remote;
    return make_error_code(Errc::NOT_IMPLEMENTED);
}

std::error_code TcpTransport::send(Packet&& pkt, const Endpoint& to) {
    (void)pkt; (void)to;
    return make_error_code(Errc::NOT_IMPLEMENTED);
}

void TcpTransport::close() noexcept {}

} // namespace smo
