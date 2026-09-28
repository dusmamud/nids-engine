#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include "nids/common/types.hpp"

namespace nids::protocol {

struct IPv4Packet {
    uint8_t version{4};
    uint8_t ihl_bytes{20};
    uint8_t dscp{0};
    uint16_t total_length{0};
    uint16_t identification{0};
    bool dont_fragment{false};
    bool more_fragments{false};
    uint16_t fragment_offset{0};
    uint8_t ttl{0};
    common::TransportProtocol protocol{common::TransportProtocol::UNKNOWN};
    uint16_t checksum{0};
    common::IPv4Address source_ip;
    common::IPv4Address destination_ip;
    std::span<const uint8_t> payload;
};

class IPv4Dissector {
public:
    static constexpr size_t MIN_HEADER_SIZE = 20;

    [[nodiscard]] static std::optional<IPv4Packet> dissect(std::span<const uint8_t> raw_bytes) noexcept;
    [[nodiscard]] static bool verify_checksum(std::span<const uint8_t> header_bytes) noexcept;
};

} // namespace nids::protocol
