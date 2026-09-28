#include "nids/output/alert_logger.hpp"

#include <chrono>
#include <iostream>
#include <sstream>

namespace nids::output {

AlertLogger::AlertLogger(const std::string& log_file_path, bool echo_console)
    : file_path_(log_file_path), echo_console_(echo_console) {
    out_file_.open(file_path_, std::ios::out | std::ios::app);
}

AlertLogger::~AlertLogger() {
    if (out_file_.is_open()) {
        out_file_.flush();
        out_file_.close();
    }
}

std::string AlertLogger::severity_to_string(detection::ThreatSeverity s) noexcept {
    switch (s) {
        case detection::ThreatSeverity::INFO:     return "INFO";
        case detection::ThreatSeverity::LOW:      return "LOW";
        case detection::ThreatSeverity::MEDIUM:   return "MEDIUM";
        case detection::ThreatSeverity::HIGH:     return "HIGH";
        case detection::ThreatSeverity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

void AlertLogger::log_alert(const detection::ThreatAlert& alert) {
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
        alert.timestamp.time_since_epoch()).count();

    std::ostringstream json;
    json << "{\"timestamp_ms\":" << millis
         << ",\"rule\":\"" << alert.rule_name << "\""
         << ",\"severity\":\"" << severity_to_string(alert.severity) << "\""
         << ",\"src_ip\":\"" << alert.source_ip.to_string() << "\""
         << ",\"dst_ip\":\"" << alert.destination_ip.to_string() << "\""
         << ",\"src_port\":" << alert.source_port
         << ",\"dst_port\":" << alert.destination_port
         << ",\"description\":\"" << alert.description << "\"}";

    const std::string json_str = json.str();

    std::lock_guard<std::mutex> lock(write_mutex_);

    if (echo_console_) {
        std::cerr << "[" << severity_to_string(alert.severity) << "] "
                  << alert.rule_name << " (" << alert.source_ip.to_string()
                  << " -> " << alert.destination_ip.to_string() << ":" << alert.destination_port
                  << "): " << alert.description << "\n";
    }

    if (out_file_.is_open()) {
        out_file_ << json_str << "\n";
        out_file_.flush();
    }
}

} // namespace nids::output
