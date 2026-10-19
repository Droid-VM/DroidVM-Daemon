// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <memory>
#include <vector>

namespace droidvm {
struct HostOverviewHost {
    std::optional<std::string> kernel_release, machine, device_model, soc_model;
};
struct HostOverviewDaemon { int64_t pid = 0; std::string version; };
struct HostOverviewCpu {
    std::optional<uint32_t> logical_count;
    std::optional<double> usage_percent;
    std::optional<uint64_t> sample_window_ms;
};
struct HostOverviewMemory { std::optional<uint64_t> total_bytes, available_bytes; };
struct HostOverviewStorage { std::optional<uint64_t> total_bytes, free_bytes, available_bytes; };
struct HostOverviewInventory {
    std::optional<uint32_t> vm_count, running_vm_count, network_count, running_network_count, disk_count;
    std::optional<uint64_t> disk_virtual_bytes;
    std::optional<uint32_t> disk_virtual_known_count;
    std::optional<uint64_t> disk_virtual_observed_at_ms;
};
struct HostOverview {
    uint64_t observed_at_ms = 0;
    HostOverviewHost host;
    HostOverviewDaemon daemon;
    HostOverviewCpu cpu;
    HostOverviewMemory memory;
    HostOverviewStorage storage;
    // Populated by the caller from the existing resource services. Resource
    // inventory and these OS observations are not one atomic host snapshot.
    HostOverviewInventory inventory;
};
struct HostOverviewOptions {
    std::string data_directory;
    std::string proc_directory = "/proc";
    HostOverviewHost host; // main supplies Android properties via host_facts.
    HostOverviewDaemon daemon;
    // Dependency seams for host fixtures; no path/function comes from HTTP.
    std::function<std::optional<std::string>(const std::string&)> read_file;
    std::function<HostOverviewStorage(const std::string&)> storage;
    std::function<std::chrono::steady_clock::time_point()> monotonic;
    std::function<uint64_t()> wall_ms;
};
// Request-driven, bounded observations; never creates a sampling thread.
// A shared 1s cache bounds proc/sys reads across browser sessions. CPU needs
// two samples; counter resets and gaps over 30s establish a new baseline.
class HostOverviewService {
public:
    explicit HostOverviewService(HostOverviewOptions options);
    HostOverview snapshot();
private:
    using Clock = std::chrono::steady_clock;
    struct CpuSample { std::array<uint64_t, 8> ticks{}; Clock::time_point at; };
    HostOverviewOptions options_;
    std::mutex mutex_;
    std::optional<HostOverview> cached_;
    Clock::time_point cached_at_{};
    std::optional<CpuSample> previous_cpu_;
};
struct HostDiskCapacityView {
    uint32_t known_count = 0;
    std::optional<uint64_t> total_bytes, observed_at_ms;
};
// Reuses the caller's bounded worker pool. One image inspection per queued job;
// HTTP only reads cached values and enqueues a scan. Failed/busy/stale members
// keep the aggregate unknown. Never derives virtual capacity from file length.
class HostDiskCapacity {
public:
    using Inspect = std::function<std::optional<uint64_t>(const std::string& id, const std::string& revision)>;
    using Post = std::function<void(std::function<void(bool discarded)>)>;
    HostDiskCapacity(Inspect inspect, Post post);
    HostDiskCapacityView read(std::string revision, std::vector<std::string> ids);
private:
    struct Shared;
    std::shared_ptr<Shared> shared_;
    static void schedule(const std::shared_ptr<Shared>& state);
};
}
