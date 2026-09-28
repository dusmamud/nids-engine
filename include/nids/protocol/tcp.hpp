#pragma once

#include <cstdint>
#include <optional>
#include <span>

namespace nids::protocol {

struct TCPFlags {
    bool fin{false};
    bool syn{false};
    bool rst{false};
    bool psh{false};
    bool ack{false};
    bool urg{false};
    bool ece{false};
    bool cwr{false};
};

struct TCPSegment {
    uint16_t source_port{0};
    uint16_t destination_port{0};
    uint32_t sequence_number{0};
    uint32_t acknowledgment_number{0};
    uint8_t data_offset_bytes{20};
    TCPFlags flags{};
    uint16_t window_size{0};
    uint16_t checksum{0};
    uint16_t urgent_pointer{0};
    std::span<const uint8_t> payload;
};

class TCPDissector {
public:
    static constexpr size_t MIN_HEADER_SIZE = 20;

    [[nodiscard]] static std::optional<TCPSegment> dissect(std::span<const uint8_t> raw_bytes) noexcept;
};

} // namespace nids::protocol
