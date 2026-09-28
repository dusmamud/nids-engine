#include "nids/detection/entropy_detector.hpp"

#include <array>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace nids::detection {

EntropyDetector::EntropyDetector(double threshold, size_t min_payload_bytes)
    : threshold_(threshold), min_payload_bytes_(min_payload_bytes) {}

double EntropyDetector::calculate_entropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<size_t, 256> frequencies{};
    for (const uint8_t byte : data) {
        frequencies[byte]++;
    }

    const double data_len = static_cast<double>(data.size());
    double entropy = 0.0;

    for (const size_t count : frequencies) {
        if (count == 0) continue;
        const double p = static_cast<double>(count) / data_len;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

std::optional<ThreatAlert> EntropyDetector::inspect_payload(
    std::span<const uint8_t> payload,
    common::IPv4Address src_ip,
    common::IPv4Address dst_ip,
    uint16_t src_port,
    uint16_t dst_port
) const {
    if (payload.size() < min_payload_bytes_) {
        return std::nullopt;
    }

    const double entropy = calculate_entropy(payload);
    if (entropy >= threshold_) {
        ThreatAlert alert;
        alert.rule_name = "HIGH_ENTROPY_PAYLOAD_ANOMALY";
        alert.severity = ThreatSeverity::HIGH;
        alert.source_ip = src_ip;
        alert.destination_ip = dst_ip;
        alert.source_port = src_port;
        alert.destination_port = dst_port;
        alert.timestamp = std::chrono::system_clock::now();

        std::ostringstream oss;
        oss << "Payload size " << payload.size() << " bytes exhibited high Shannon entropy: "
            << std::fixed << std::setprecision(2) << entropy << " (Threshold: " << threshold_
            << "), indicating packed malware shellcode or encrypted exfiltration.";
        alert.description = oss.str();

        return alert;
    }

    return std::nullopt;
}

} // namespace nids::detection
