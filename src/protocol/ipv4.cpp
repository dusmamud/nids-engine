#include "nids/protocol/ipv4.hpp"

namespace nids::protocol {

std::optional<IPv4Packet> IPv4Dissector::dissect(std::span<const uint8_t> raw_bytes) noexcept {
    if (raw_bytes.size() < MIN_HEADER_SIZE) {
        return std::nullopt;
    }

    const uint8_t ver_ihl = raw_bytes[0];
    const uint8_t version = static_cast<uint8_t>(ver_ihl >> 4);
    const uint8_t ihl_words = static_cast<uint8_t>(ver_ihl & 0x0F);
    const size_t ihl_bytes = static_cast<size_t>(ihl_words * 4);

    if (version != 4 || ihl_bytes < MIN_HEADER_SIZE || raw_bytes.size() < ihl_bytes) {
        return std::nullopt;
    }

    const uint16_t total_len = static_cast<uint16_t>((raw_bytes[2] << 8) | raw_bytes[3]);
    if (raw_bytes.size() < total_len || total_len < ihl_bytes) {
        return std::nullopt;
    }

    IPv4Packet packet;
    packet.version = version;
    packet.ihl_bytes = static_cast<uint8_t>(ihl_bytes);
    packet.dscp = static_cast<uint8_t>(raw_bytes[1] >> 2);
    packet.total_length = total_len;
    packet.identification = static_cast<uint16_t>((raw_bytes[4] << 8) | raw_bytes[5]);

    const uint16_t flags_frag = static_cast<uint16_t>((raw_bytes[6] << 8) | raw_bytes[7]);
    packet.dont_fragment = (flags_frag & 0x4000) != 0;
    packet.more_fragments = (flags_frag & 0x2000) != 0;
    packet.fragment_offset = static_cast<uint16_t>((flags_frag & 0x1FFF) * 8);

    packet.ttl = raw_bytes[8];
    packet.protocol = static_cast<common::TransportProtocol>(raw_bytes[9]);
    packet.checksum = static_cast<uint16_t>((raw_bytes[10] << 8) | raw_bytes[11]);

    const uint32_t src_ip_raw = (static_cast<uint32_t>(raw_bytes[12]) << 24) |
                                (static_cast<uint32_t>(raw_bytes[13]) << 16) |
                                (static_cast<uint32_t>(raw_bytes[14]) << 8)  |
                                static_cast<uint32_t>(raw_bytes[15]);

    const uint32_t dst_ip_raw = (static_cast<uint32_t>(raw_bytes[16]) << 24) |
                                (static_cast<uint32_t>(raw_bytes[17]) << 16) |
                                (static_cast<uint32_t>(raw_bytes[18]) << 8)  |
                                static_cast<uint32_t>(raw_bytes[19]);

    packet.source_ip = common::IPv4Address(src_ip_raw);
    packet.destination_ip = common::IPv4Address(dst_ip_raw);

    const size_t payload_len = total_len - ihl_bytes;
    packet.payload = raw_bytes.subspan(ihl_bytes, payload_len);

    return packet;
}

bool IPv4Dissector::verify_checksum(std::span<const uint8_t> header_bytes) noexcept {
    if (header_bytes.size() < MIN_HEADER_SIZE) return false;

    uint32_t sum = 0;
    for (size_t i = 0; i < header_bytes.size() - 1; i += 2) {
        const uint16_t word = static_cast<uint16_t>((header_bytes[i] << 8) | header_bytes[i + 1]);
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum) == 0;
}

} // namespace nids::protocol
