#include "nids/detection/port_scan_detector.hpp"

#include <algorithm>
#include <sstream>

namespace nids::detection {

PortScanDetector::PortScanDetector(size_t threshold, std::chrono::seconds window)
    : threshold_(threshold), window_(window) {}

std::optional<ThreatAlert> PortScanDetector::record_syn_attempt(
    common::IPv4Address src_ip,
    common::IPv4Address dst_ip,
    uint16_t dst_port
) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    auto& history = scan_tracker_[src_ip.value()];
    history.attempts.push_back({now, dst_port});

    // Prune entries outside the sliding window
    const auto cutoff = now - window_;
    history.attempts.erase(
        std::remove_if(history.attempts.begin(), history.attempts.end(),
                       [cutoff](const PortAttempt& pa) { return pa.timestamp < cutoff; }),
        history.attempts.end()
    );

    // Count unique ports hit in this window
    std::unordered_set<uint16_t> unique_ports;
    for (const auto& attempt : history.attempts) {
        unique_ports.insert(attempt.dst_port);
    }

    if (unique_ports.size() >= threshold_) {
        // Enforce cooldown so we don't spam alerts every packet
        if (history.last_alert_time.time_since_epoch().count() > 0 &&
            (now - history.last_alert_time) < window_) {
            return std::nullopt;
        }

        history.last_alert_time = now;

        ThreatAlert alert;
        alert.rule_name = "RECON_PORT_SCAN_DETECTED";
        alert.severity = ThreatSeverity::HIGH;
        alert.source_ip = src_ip;
        alert.destination_ip = dst_ip;
        alert.source_port = 0;
        alert.destination_port = dst_port;
        alert.timestamp = std::chrono::system_clock::now();

        std::ostringstream oss;
        oss << "Host " << src_ip.to_string() << " hit " << unique_ports.size()
            << " unique ports within " << window_.count() << " seconds. Reconnaissance scan suspected.";
        alert.description = oss.str();

        return alert;
    }

    return std::nullopt;
}

} // namespace nids::detection
