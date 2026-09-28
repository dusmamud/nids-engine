#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include "nids/flow/flow_key.hpp"

namespace nids::flow {

struct FlowMetrics {
    uint64_t packet_count{0};
    uint64_t byte_count{0};
    uint32_t syn_count{0};
    uint32_t ack_count{0};
    uint32_t rst_count{0};
    uint32_t fin_count{0};
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};

class ShardedFlowTable {
public:
    static constexpr size_t NUM_SHARDS = 16;

    ShardedFlowTable();
    ~ShardedFlowTable() = default;

    void record_packet(const FlowKey& key, size_t packet_bytes, bool syn, bool ack, bool rst, bool fin);
    [[nodiscard]] std::optional<FlowMetrics> get_metrics(const FlowKey& key) const;
    [[nodiscard]] size_t total_active_flows() const;
    void prune_inactive_flows(std::chrono::seconds timeout);

private:
    struct Shard {
        mutable std::shared_mutex mutex;
        std::unordered_map<FlowKey, FlowMetrics> map;
    };

    [[nodiscard]] size_t get_shard_index(const FlowKey& key) const noexcept;

    std::array<Shard, NUM_SHARDS> shards_;
};

} // namespace nids::flow
