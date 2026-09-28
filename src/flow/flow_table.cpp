#include "nids/flow/flow_table.hpp"

namespace nids::flow {

ShardedFlowTable::ShardedFlowTable() = default;

size_t ShardedFlowTable::get_shard_index(const FlowKey& key) const noexcept {
    return std::hash<FlowKey>{}(key.canonical()) % NUM_SHARDS;
}

void ShardedFlowTable::record_packet(const FlowKey& key, size_t packet_bytes,
                                     bool syn, bool ack, bool rst, bool fin) {
    const FlowKey canonical_key = key.canonical();
    const size_t shard_idx = get_shard_index(canonical_key);
    auto& shard = shards_[shard_idx];

    const auto now = std::chrono::steady_clock::now();

    std::unique_lock<std::shared_mutex> lock(shard.mutex);
    auto it = shard.map.find(canonical_key);
    if (it == shard.map.end()) {
        FlowMetrics metrics;
        metrics.packet_count = 1;
        metrics.byte_count = packet_bytes;
        metrics.syn_count = syn ? 1 : 0;
        metrics.ack_count = ack ? 1 : 0;
        metrics.rst_count = rst ? 1 : 0;
        metrics.fin_count = fin ? 1 : 0;
        metrics.first_seen = now;
        metrics.last_seen = now;
        shard.map.emplace(canonical_key, metrics);
    } else {
        it->second.packet_count += 1;
        it->second.byte_count += packet_bytes;
        if (syn) it->second.syn_count += 1;
        if (ack) it->second.ack_count += 1;
        if (rst) it->second.rst_count += 1;
        if (fin) it->second.fin_count += 1;
        it->second.last_seen = now;
    }
}

std::optional<FlowMetrics> ShardedFlowTable::get_metrics(const FlowKey& key) const {
    const FlowKey canonical_key = key.canonical();
    const size_t shard_idx = get_shard_index(canonical_key);
    const auto& shard = shards_[shard_idx];

    std::shared_lock<std::shared_mutex> lock(shard.mutex);
    auto it = shard.map.find(canonical_key);
    if (it != shard.map.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t ShardedFlowTable::total_active_flows() const {
    size_t count = 0;
    for (const auto& shard : shards_) {
        std::shared_lock<std::shared_mutex> lock(shard.mutex);
        count += shard.map.size();
    }
    return count;
}

void ShardedFlowTable::prune_inactive_flows(std::chrono::seconds timeout) {
    const auto now = std::chrono::steady_clock::now();
    for (auto& shard : shards_) {
        std::unique_lock<std::shared_mutex> lock(shard.mutex);
        for (auto it = shard.map.begin(); it != shard.map.end();) {
            if (now - it->second.last_seen > timeout) {
                it = shard.map.erase(it);
            } else {
                ++it;
            }
        }
    }
}

} // namespace nids::flow
