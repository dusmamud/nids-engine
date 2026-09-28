#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include "nids/common/types.hpp"

namespace nids::detection {

enum class ThreatSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct ThreatAlert {
    std::string rule_name;
    ThreatSeverity severity{ThreatSeverity::MEDIUM};
    common::IPv4Address source_ip;
    common::IPv4Address destination_ip;
    uint16_t source_port{0};
    uint16_t destination_port{0};
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

class IDetector {
public:
    virtual ~IDetector() = default;
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

} // namespace nids::detection
