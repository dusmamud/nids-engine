#include "nids/detection/syn_flood_detector.hpp"

#include <iomanip>
#include <sstream>

namespace nids::detection {

SynFloodDetector::SynFloodDetector(uint32_t min_syn_count, double ratio_threshold)
    : min_syn_count_(min_syn_count), ratio_threshold_(ratio_threshold) {}

std::optional<ThreatAlert> SynFloodDetector::record_flags(
    common::IPv4Address src_ip,
    common::IPv4Address dst_ip,
    bool is_syn,
    bool is_ack
) {
    if (!is_syn && !is_ack) return std::nullopt;

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    auto& entry = counters_[src_ip.value()];
    if (is_syn) entry.syn_count++;
    if (is_ack) entry.ack_count++;

    if (entry.syn_count >= min_syn_count_) {
        const double total = static_cast<double>(entry.syn_count + entry.ack_count);
        const double syn_ratio = static_cast<double>(entry.syn_count) / total;

        if (syn_ratio >= ratio_threshold_) {
            if (entry.last_alert_time.time_since_epoch().count() > 0 &&
                (now - entry.last_alert_time) < std::chrono::seconds(10)) {
                return std::nullopt;
            }

            entry.last_alert_time = now;

            ThreatAlert alert;
            alert.rule_name = "DOS_SYN_FLOOD_SUSPECTED";
            alert.severity = ThreatSeverity::CRITICAL;
            alert.source_ip = src_ip;
            alert.destination_ip = dst_ip;
            alert.source_port = 0;
            alert.destination_port = 0;
            alert.timestamp = std::chrono::system_clock::now();

            std::ostringstream oss;
            oss << "Host " << src_ip.to_string() << " sent " << entry.syn_count
                << " SYN packets against " << entry.ack_count << " ACKs (SYN Ratio: "
                << std::fixed << std::setprecision(2) << (syn_ratio * 100.0)
                << "%), exceeding threshold ratio " << (ratio_threshold_ * 100.0) << "%.";
            alert.description = oss.str();

            return alert;
        }
    }

    return std::nullopt;
}

} // namespace nids::detection
