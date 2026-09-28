#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace nids::common {

enum class TransportProtocol : uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    UNKNOWN = 255
};

struct MacAddress {
    std::array<uint8_t, 6> octets{};

    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        for (size_t i = 0; i < octets.size(); ++i) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(octets[i]);
        }
        return oss.str();
    }

    auto operator<=>(const MacAddress&) const = default;
};

class IPv4Address {
public:
    constexpr IPv4Address() : raw_address_(0) {}
    constexpr explicit IPv4Address(uint32_t host_order_addr) : raw_address_(host_order_addr) {}

    [[nodiscard]] constexpr uint32_t value() const noexcept { return raw_address_; }

    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        oss << ((raw_address_ >> 24) & 0xFF) << "."
            << ((raw_address_ >> 16) & 0xFF) << "."
            << ((raw_address_ >> 8) & 0xFF) << "."
            << (raw_address_ & 0xFF);
        return oss.str();
    }

    auto operator<=>(const IPv4Address&) const = default;

private:
    uint32_t raw_address_{0};
};

using Timestamp = std::chrono::time_point<std::chrono::system_clock>;

} // namespace nids::common
