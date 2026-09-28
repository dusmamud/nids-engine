#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include "nids/common/types.hpp"

namespace nids::protocol {

enum class EtherType : uint16_t {
    IPv4 = 0x0800,
    ARP  = 0x0806,
    IPv6 = 0x86DD,
    VLAN = 0x8100,
    UNKNOWN = 0xFFFF
};

struct EthernetFrame {
    common::MacAddress destination;
    common::MacAddress source;
    EtherType ethertype{EtherType::UNKNOWN};
    std::span<const uint8_t> payload;
};

class EthernetDissector {
public:
    static constexpr size_t HEADER_SIZE = 14;

    [[nodiscard]] static std::optional<EthernetFrame> dissect(std::span<const uint8_t> raw_bytes) noexcept;
};

} // namespace nids::protocol
