#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "nids/detection/idetector.hpp"

namespace nids::detection {

class PortScanDetector : public IDetector {
public:
    explicit PortScanDetector(size_t threshold = 15, std::chrono::seconds window = std::chrono::seconds(5));

    [[nodiscard]] std::string_view name() const noexcept override {
        return "SlidingWindowPortScanDetector";
    }

    [[nodiscard]] std::optional<ThreatAlert> record_syn_attempt(
        common::IPv4Address src_ip,
        common::IPv4Address dst_ip,
        uint16_t dst_port
    );

private:
    struct PortAttempt {
        std::chrono::steady_clock::time_point timestamp;
        uint16_t dst_port;
    };

    struct HostScanHistory {
        std::vector<PortAttempt> attempts;
        std::chrono::steady_clock::time_point last_alert_time;
    };

    size_t threshold_{15};
    std::chrono::seconds window_{5};
    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, HostScanHistory> scan_tracker_;
};

} // namespace nids::detection
