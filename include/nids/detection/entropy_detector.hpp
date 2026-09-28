#pragma once

#include <optional>
#include <span>
#include "nids/detection/idetector.hpp"

namespace nids::detection {

class EntropyDetector : public IDetector {
public:
    explicit EntropyDetector(double threshold = 7.5, size_t min_payload_bytes = 32);

    [[nodiscard]] std::string_view name() const noexcept override {
        return "ShannonEntropyPayloadDetector";
    }

    [[nodiscard]] static double calculate_entropy(std::span<const uint8_t> data) noexcept;

    [[nodiscard]] std::optional<ThreatAlert> inspect_payload(
        std::span<const uint8_t> payload,
        common::IPv4Address src_ip,
        common::IPv4Address dst_ip,
        uint16_t src_port,
        uint16_t dst_port
    ) const;

private:
    double threshold_{7.5};
    size_t min_payload_bytes_{32};
};

} // namespace nids::detection
