#include <cassert>
#include <functional>
#include <string>
#include <vector>
#include "nids/protocol/ethernet.hpp"
#include "nids/protocol/ipv4.hpp"
#include "nids/protocol/tcp.hpp"

namespace test_runner {
void register_test(const std::string& name, std::function<void()> func);
}

namespace {

void test_ethernet_dissection() {
    // 14-byte Ethernet frame: Dst MAC (00:11:22:33:44:55), Src MAC (AA:BB:CC:DD:EE:FF), EtherType 0x0800 (IPv4)
    std::vector<uint8_t> raw = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28 // Trailing payload
    };

    auto frame = nids::protocol::EthernetDissector::dissect(raw);
    assert(frame.has_value());
    assert(frame->destination.to_string() == "00:11:22:33:44:55");
    assert(frame->source.to_string() == "aa:bb:cc:dd:ee:ff");
    assert(frame->ethertype == nids::protocol::EtherType::IPv4);
    assert(frame->payload.size() == 4);
}

void test_ipv4_dissection() {
    // 20-byte standard IPv4 header: 192.168.1.100 -> 10.0.0.1, TCP (protocol 6), Total len = 40
    std::vector<uint8_t> raw = {
        0x45, 0x00, 0x00, 0x28, // Ver 4, IHL 5, DSCP 0, Total len 40
        0x12, 0x34, 0x40, 0x00, // ID, Flags (DF)
        0x40, 0x06, 0x00, 0x00, // TTL 64, Protocol TCP, Checksum
        192, 168, 1, 100,       // Src IP
        10, 0, 0, 1,            // Dst IP
        // 20 bytes payload
        0x00, 0x50, 0x1F, 0x90, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    auto packet = nids::protocol::IPv4Dissector::dissect(raw);
    assert(packet.has_value());
    assert(packet->version == 4);
    assert(packet->ihl_bytes == 20);
    assert(packet->total_length == 40);
    assert(packet->source_ip.to_string() == "192.168.1.100");
    assert(packet->destination_ip.to_string() == "10.0.0.1");
    assert(packet->protocol == nids::common::TransportProtocol::TCP);
    assert(packet->payload.size() == 20);
}

void test_tcp_dissection() {
    // 20-byte TCP header: Port 80 -> Port 8080, SYN flag
    std::vector<uint8_t> raw = {
        0x00, 0x50,             // Src Port: 80
        0x1F, 0x90,             // Dst Port: 8080
        0x00, 0x00, 0x00, 0x42, // Seq num: 66
        0x00, 0x00, 0x00, 0x00, // Ack num: 0
        0x50,                   // Data offset: 5 (20 bytes)
        0x02,                   // Flags: SYN
        0x20, 0x00,             // Window size: 8192
        0x12, 0x34,             // Checksum
        0x00, 0x00              // Urgent pointer
    };

    auto segment = nids::protocol::TCPDissector::dissect(raw);
    assert(segment.has_value());
    assert(segment->source_port == 80);
    assert(segment->destination_port == 8080);
    assert(segment->sequence_number == 66);
    assert(segment->flags.syn == true);
    assert(segment->flags.ack == false);
    assert(segment->payload.empty());
}

struct RegisterDissectorTests {
    RegisterDissectorTests() {
        test_runner::register_test("Ethernet Dissector Boundary Test", test_ethernet_dissection);
        test_runner::register_test("IPv4 Dissector Header Parsing", test_ipv4_dissection);
        test_runner::register_test("TCP Dissector Flags Validation", test_tcp_dissection);
    }
} g_register_dissector_tests;

} // namespace
