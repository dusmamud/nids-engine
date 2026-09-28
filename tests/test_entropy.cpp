#include <cassert>
#include <cmath>
#include <vector>
#include "nids/detection/entropy_detector.hpp"

namespace test_runner {
void register_test(const std::string& name, std::function<void()> func);
}

namespace {

void test_entropy_zero_for_constant_bytes() {
    // Repeated single byte has zero entropy (zero uncertainty)
    std::vector<uint8_t> constant_buffer(64, 'A');
    const double entropy = nids::detection::EntropyDetector::calculate_entropy(constant_buffer);
    assert(std::abs(entropy - 0.0) < 0.001);
}

void test_entropy_max_for_uniform_distribution() {
    // All 256 byte values present in equal proportions -> maximum entropy = 8.0 bits
    std::vector<uint8_t> uniform_buffer;
    uniform_buffer.reserve(256 * 4);
    for (int rep = 0; rep < 4; ++rep) {
        for (int b = 0; b < 256; ++b) {
            uniform_buffer.push_back(static_cast<uint8_t>(b));
        }
    }

    const double entropy = nids::detection::EntropyDetector::calculate_entropy(uniform_buffer);
    assert(std::abs(entropy - 8.0) < 0.001);
}

void test_entropy_detector_alert_trigger() {
    nids::detection::EntropyDetector detector(7.5, 32);

    // Uniform random-like buffer should trigger alert (entropy = 8.0 >= 7.5)
    std::vector<uint8_t> high_entropy_buffer;
    for (int b = 0; b < 256; ++b) {
        high_entropy_buffer.push_back(static_cast<uint8_t>(b));
    }

    auto alert = detector.inspect_payload(
        high_entropy_buffer,
        nids::common::IPv4Address(0x0A000001),
        nids::common::IPv4Address(0x0A000002),
        4444,
        80
    );

    assert(alert.has_value());
    assert(alert->rule_name == "HIGH_ENTROPY_PAYLOAD_ANOMALY");
    assert(alert->severity == nids::detection::ThreatSeverity::HIGH);
}

struct RegisterEntropyTests {
    RegisterEntropyTests() {
        test_runner::register_test("Entropy Zero on Monotonous Buffer", test_entropy_zero_for_constant_bytes);
        test_runner::register_test("Entropy Max on Uniform Distribution", test_entropy_max_for_uniform_distribution);
        test_runner::register_test("Entropy Detector Anomaly Trigger", test_entropy_detector_alert_trigger);
    }
} g_register_entropy_tests;

} // namespace
