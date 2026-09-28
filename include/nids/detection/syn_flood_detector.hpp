#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>
#include "nids/detection/idetector.hpp"

namespace nids::detection {

class SynFloodDetector : public IDetector {
public:
    explicit SynFloodDetector(uint32_t min_syn_count = 100, double ratio_threshold = 0.85);

    [[nodiscard]] std::string_view name() const noexcept override {
        return "SynFloodAsymmetryDetector";
    }

    [[nodiscard]] std::optional<ThreatAlert> record_flags(
        common::IPv4Address src_ip,
        common::IPv4Address dst_ip,
        bool is_syn,
        bool is_ack
    );

private:
    struct HostCounters {
        uint32_t syn_count{0};
        uint32_t ack_count{0};
        std::chrono::steady_clock::time_point last_alert_time;
    };

    uint32_t min_syn_count_{100};
    double ratio_threshold_{0.85};
    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, HostCounters> counters_;
};

} // namespace nids::detection
