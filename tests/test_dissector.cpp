#include <vector>
#include "test_runner.hpp"
#include "nids/protocol/ethernet.hpp"
#include "nids/protocol/ipv4.hpp"
#include "nids/protocol/tcp.hpp"

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
    TEST_ASSERT(frame.has_value());
    TEST_ASSERT(frame->destination.to_string() == "00:11:22:33:44:55");
    TEST_ASSERT(frame->source.to_string() == "aa:bb:cc:dd:ee:ff");
    TEST_ASSERT(frame->ethertype == nids::protocol::EtherType::IPv4);
    TEST_ASSERT(frame->payload.size() == 4);
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
    TEST_ASSERT(packet.has_value());
    TEST_ASSERT(packet->version == 4);
    TEST_ASSERT(packet->ihl_bytes == 20);
    TEST_ASSERT(packet->total_length == 40);
    TEST_ASSERT(packet->source_ip.to_string() == "192.168.1.100");
    TEST_ASSERT(packet->destination_ip.to_string() == "10.0.0.1");
    TEST_ASSERT(packet->protocol == nids::common::TransportProtocol::TCP);
    TEST_ASSERT(packet->payload.size() == 20);
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
    TEST_ASSERT(segment.has_value());
    TEST_ASSERT(segment->source_port == 80);
    TEST_ASSERT(segment->destination_port == 8080);
    TEST_ASSERT(segment->sequence_number == 66);
    TEST_ASSERT(segment->flags.syn == true);
    TEST_ASSERT(segment->flags.ack == false);
    TEST_ASSERT(segment->payload.empty());
}

struct RegisterDissectorTests {
    RegisterDissectorTests() {
        test_runner::register_test("Ethernet Dissector Boundary Test", test_ethernet_dissection);
        test_runner::register_test("IPv4 Dissector Header Parsing", test_ipv4_dissection);
        test_runner::register_test("TCP Dissector Flags Validation", test_tcp_dissection);
    }
} g_register_dissector_tests;

} // namespace
