#include "nids/protocol/tcp.hpp"

namespace nids::protocol {

std::optional<TCPSegment> TCPDissector::dissect(std::span<const uint8_t> raw_bytes) noexcept {
    if (raw_bytes.size() < MIN_HEADER_SIZE) {
        return std::nullopt;
    }

    const uint8_t data_offset_words = static_cast<uint8_t>(raw_bytes[12] >> 4);
    const size_t data_offset_bytes = static_cast<size_t>(data_offset_words * 4);

    if (data_offset_bytes < MIN_HEADER_SIZE || raw_bytes.size() < data_offset_bytes) {
        return std::nullopt;
    }

    TCPSegment segment;
    segment.source_port = static_cast<uint16_t>((raw_bytes[0] << 8) | raw_bytes[1]);
    segment.destination_port = static_cast<uint16_t>((raw_bytes[2] << 8) | raw_bytes[3]);
    segment.sequence_number = (static_cast<uint32_t>(raw_bytes[4]) << 24) |
                              (static_cast<uint32_t>(raw_bytes[5]) << 16) |
                              (static_cast<uint32_t>(raw_bytes[6]) << 8)  |
                              static_cast<uint32_t>(raw_bytes[7]);

    segment.acknowledgment_number = (static_cast<uint32_t>(raw_bytes[8]) << 24)  |
                                    (static_cast<uint32_t>(raw_bytes[9]) << 16)  |
                                    (static_cast<uint32_t>(raw_bytes[10]) << 8)  |
                                    static_cast<uint32_t>(raw_bytes[11]);

    segment.data_offset_bytes = static_cast<uint8_t>(data_offset_bytes);

    const uint8_t flag_byte = raw_bytes[13];
    segment.flags.fin = (flag_byte & 0x01) != 0;
    segment.flags.syn = (flag_byte & 0x02) != 0;
    segment.flags.rst = (flag_byte & 0x04) != 0;
    segment.flags.psh = (flag_byte & 0x08) != 0;
    segment.flags.ack = (flag_byte & 0x10) != 0;
    segment.flags.urg = (flag_byte & 0x20) != 0;
    segment.flags.ece = (flag_byte & 0x40) != 0;
    segment.flags.cwr = (flag_byte & 0x80) != 0;

    segment.window_size = static_cast<uint16_t>((raw_bytes[14] << 8) | raw_bytes[15]);
    segment.checksum = static_cast<uint16_t>((raw_bytes[16] << 8) | raw_bytes[17]);
    segment.urgent_pointer = static_cast<uint16_t>((raw_bytes[18] << 8) | raw_bytes[19]);

    segment.payload = raw_bytes.subspan(data_offset_bytes);
    return segment;
}

} // namespace nids::protocol
