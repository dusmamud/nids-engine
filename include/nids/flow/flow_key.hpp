#pragma once

#include <cstdint>
#include <functional>
#include "nids/common/types.hpp"

namespace nids::flow {

struct FlowKey {
    common::IPv4Address src_ip;
    common::IPv4Address dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    common::TransportProtocol protocol{common::TransportProtocol::UNKNOWN};

    [[nodiscard]] FlowKey canonical() const noexcept {
        const bool should_swap = (src_ip.value() > dst_ip.value()) ||
                                 (src_ip.value() == dst_ip.value() && src_port > dst_port);
        if (should_swap) {
            return FlowKey{dst_ip, src_ip, dst_port, src_port, protocol};
        }
        return *this;
    }

    auto operator<=>(const FlowKey&) const = default;
};

} // namespace nids::flow

namespace std {
template <>
struct hash<nids::flow::FlowKey> {
    size_t operator()(const nids::flow::FlowKey& k) const noexcept {
        size_t h1 = std::hash<uint32_t>{}(k.src_ip.value());
        size_t h2 = std::hash<uint32_t>{}(k.dst_ip.value());
        size_t h3 = std::hash<uint16_t>{}(k.src_port);
        size_t h4 = std::hash<uint16_t>{}(k.dst_port);
        size_t h5 = std::hash<uint8_t>{}(static_cast<uint8_t>(k.protocol));

        // Combined 64-bit FNV-1a inspired hash mixing
        size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h4 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h5 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
};
} // namespace std
