#pragma once

#include <fstream>
#include <mutex>
#include <string>
#include "nids/detection/idetector.hpp"

namespace nids::output {

class AlertLogger {
public:
    explicit AlertLogger(const std::string& log_file_path = "alerts.json", bool echo_console = true);
    ~AlertLogger();

    void log_alert(const detection::ThreatAlert& alert);

private:
    [[nodiscard]] static std::string severity_to_string(detection::ThreatSeverity s) noexcept;

    std::string file_path_;
    bool echo_console_{true};
    std::ofstream out_file_;
    std::mutex write_mutex_;
};

} // namespace nids::output
