#include <cassert>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include "nids/flow/flow_table.hpp"

namespace test_runner {
void register_test(const std::string& name, std::function<void()> func);
}

namespace {

void test_flow_canonical_bidirectional_mapping() {
    nids::flow::ShardedFlowTable table;

    const nids::common::IPv4Address client_ip(0xC0A80164); // 192.168.1.100
    const nids::common::IPv4Address server_ip(0x0A000001); // 10.0.0.1

    // Client -> Server packet
    nids::flow::FlowKey forward_key{
        client_ip, server_ip, 50420, 80, nids::common::TransportProtocol::TCP
    };
    table.record_packet(forward_key, 64, true, false, false, false);

    // Server -> Client reply packet (reversed addresses & ports)
    nids::flow::FlowKey reverse_key{
        server_ip, client_ip, 80, 50420, nids::common::TransportProtocol::TCP
    };
    table.record_packet(reverse_key, 128, true, true, false, false);

    assert(table.total_active_flows() == 1);

    auto metrics = table.get_metrics(forward_key);
    assert(metrics.has_value());
    assert(metrics->packet_count == 2);
    assert(metrics->byte_count == 192);
    assert(metrics->syn_count == 2);
    assert(metrics->ack_count == 1);
}

void test_flow_concurrent_sharded_inserts() {
    nids::flow::ShardedFlowTable table;
    constexpr size_t THREADS = 4;
    constexpr size_t OPS_PER_THREAD = 1000;

    std::vector<std::thread> workers;
    workers.reserve(THREADS);

    for (size_t t = 0; t < THREADS; ++t) {
        workers.emplace_back([&table, t]() {
            for (size_t i = 0; i < OPS_PER_THREAD; ++i) {
                const uint32_t src = 0x0A000000 | static_cast<uint32_t>(t * 1000 + i);
                nids::flow::FlowKey key{
                    nids::common::IPv4Address(src),
                    nids::common::IPv4Address(0x0A0000FF),
                    static_cast<uint16_t>(1024 + (i % 50000)),
                    80,
                    nids::common::TransportProtocol::TCP
                };
                table.record_packet(key, 100, true, false, false, false);
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    assert(table.total_active_flows() == THREADS * OPS_PER_THREAD);
}

struct RegisterFlowTests {
    RegisterFlowTests() {
        test_runner::register_test("Flow Canonical Bidirectional Aggregation", test_flow_canonical_bidirectional_mapping);
        test_runner::register_test("Flow Concurrent Sharded Inserts", test_flow_concurrent_sharded_inserts);
    }
} g_register_flow_tests;

} // namespace
