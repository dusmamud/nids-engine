#include "nids/protocol/ethernet.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace nids::protocol {

std::optional<EthernetFrame> EthernetDissector::dissect(std::span<const uint8_t> raw_bytes) noexcept {
    if (raw_bytes.size() < HEADER_SIZE) {
        return std::nullopt;
    }

    EthernetFrame frame;
    for (size_t i = 0; i < 6; ++i) {
        frame.destination.octets[i] = raw_bytes[i];
        frame.source.octets[i] = raw_bytes[6 + i];
    }

    const uint16_t raw_ethertype = static_cast<uint16_t>((raw_bytes[12] << 8) | raw_bytes[13]);
    frame.ethertype = static_cast<EtherType>(raw_ethertype);

    frame.payload = raw_bytes.subspan(HEADER_SIZE);
    return frame;
}

} // namespace nids::protocol
