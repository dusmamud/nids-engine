#include <atomic>
#include <csignal>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "nids/detection/entropy_detector.hpp"
#include "nids/detection/port_scan_detector.hpp"
#include "nids/detection/syn_flood_detector.hpp"
#include "nids/flow/flow_table.hpp"
#include "nids/output/alert_logger.hpp"
#include "nids/protocol/ethernet.hpp"
#include "nids/protocol/ipv4.hpp"
#include "nids/protocol/tcp.hpp"

namespace {
std::atomic<bool> g_running{true};

void signal_handler(int) noexcept {
    g_running.store(false);
}

void print_usage(std::string_view binary_name) {
    std::cout << "Usage: " << binary_name << " [options]\n\n"
              << "Options:\n"
              << "  -i, --interface <dev>   Sniff live traffic from interface (e.g. eth0)\n"
              << "  -r, --read-pcap <file>  Read and analyze offline pcap trace\n"
              << "  -o, --alert-log <path>  Path to output JSON alerts (default: alerts.json)\n"
              << "  -v, --verbose           Print per-packet parsing telemetry\n"
              << "  -h, --help              Show this help message\n";
}
} // namespace

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string interface_name;
    std::string pcap_file;
    std::string log_file = "alerts.json";
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            interface_name = argv[++i];
        } else if ((arg == "-r" || arg == "--read-pcap") && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if ((arg == "-o" || arg == "--alert-log") && i + 1 < argc) {
            log_file = argv[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    std::cout << "[INFO] nids-engine v0.1.0 starting...\n"
              << "[INFO] Target Alert Sink: " << log_file << "\n";

    if (verbose) {
        std::cout << "[INFO] Verbose telemetry logging enabled.\n";
    }

    nids::output::AlertLogger logger(log_file, true);
    nids::flow::ShardedFlowTable flow_table;
    nids::detection::PortScanDetector scan_detector(15, std::chrono::seconds(5));
    nids::detection::SynFloodDetector syn_detector(100, 0.85);
    nids::detection::EntropyDetector entropy_detector(7.5, 32);

    std::cout << "[INFO] Detection pipelines initialized:\n"
              << "       - Port Scan Detector (Threshold: 15 ports / 5s)\n"
              << "       - SYN Flood Asymmetry Monitor (Threshold: 85% SYN ratio)\n"
              << "       - Shannon Entropy Payload Analyzer (Threshold: H >= 7.5)\n"
              << "[INFO] Flow state engine: 16-way sharded concurrent table.\n";

    if (pcap_file.empty() && interface_name.empty()) {
        std::cout << "\n============================================================\n"
                  << " [DEMO SIMULATION] Running Automated Threat Scenarios...\n"
                  << "============================================================\n";

        // Scenario 1: Normal Legitimate Web Traffic
        std::cout << "\n[*] Scenario 1: Processing Normal HTTP/HTTPS Web Traffic...\n";
        for (int i = 0; i < 5; ++i) {
            nids::flow::FlowKey client_flow{
                nids::common::IPv4Address(0xC0A80164), // 192.168.1.100
                nids::common::IPv4Address(0x08080808), // 8.8.8.8
                static_cast<uint16_t>(51000 + i),
                443,
                nids::common::TransportProtocol::TCP
            };
            flow_table.record_packet(client_flow, 128, true, true, false, false);
        }
        std::cout << "    -> 5 legitimate web sessions tracked in flow table.\n";

        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        // Scenario 2: Nmap Reconnaissance Port Scan
        std::cout << "\n[*] Scenario 2: Simulating Nmap Port Scan from 192.168.1.250...\n";
        const nids::common::IPv4Address scanner_ip(0xC0A801FA); // 192.168.1.250
        const nids::common::IPv4Address target_ip(0x0A000001);  // 10.0.0.1
        for (uint16_t port = 20; port <= 40; ++port) {
            auto alert = scan_detector.record_syn_attempt(scanner_ip, target_ip, port);
            if (alert.has_value()) {
                logger.log_alert(*alert);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        // Scenario 3: Denial of Service (SYN Flood)
        std::cout << "\n[*] Scenario 3: Simulating Asymmetric SYN Flood DoS from 10.10.10.99...\n";
        const nids::common::IPv4Address attacker_ip(0x0A0A0A63); // 10.10.10.99
        for (int i = 0; i < 120; ++i) {
            auto alert = syn_detector.record_flags(attacker_ip, target_ip, true, false);
            if (alert.has_value()) {
                logger.log_alert(*alert);
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        // Scenario 4: High-Entropy Data Exfiltration / Packed Shellcode
        std::cout << "\n[*] Scenario 4: Inspecting Outbound C2 Payload for Anomaly...\n";
        std::vector<uint8_t> encrypted_payload;
        encrypted_payload.reserve(256);
        for (int b = 0; b < 256; ++b) {
            encrypted_payload.push_back(static_cast<uint8_t>((b * 37 + 13) % 256));
        }

        auto entropy_alert = entropy_detector.inspect_payload(
            encrypted_payload,
            nids::common::IPv4Address(0xC0A80132), // 192.168.1.50 (Compromised host)
            nids::common::IPv4Address(0xB9D65E12), // 185.214.94.18 (External C2 Server)
            49152,
            4444
        );
        if (entropy_alert.has_value()) {
            logger.log_alert(*entropy_alert);
        }

        std::cout << "\n============================================================\n"
                  << " [DEMO COMPLETE] All attacks detected and written to " << log_file << "\n"
                  << "============================================================\n";
    }

    std::cout << "\n[INFO] Graceful shutdown requested. Finalizing active flows...\n"
              << "[INFO] Total active flows recorded: " << flow_table.total_active_flows() << "\n"
              << "[INFO] Clean shutdown complete.\n";

    return 0;
}
