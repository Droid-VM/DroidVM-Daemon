// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_overview.h"
#include <charconv>
#include <algorithm>
#include <map>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string_view>
#ifdef _WIN32
#include <process.h>
#else
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace droidvm {
namespace {
constexpr size_t text_limit = 64u << 10;
std::string_view trim(std::string_view value) {
    while (!value.empty() && static_cast<unsigned char>(value.front()) <= ' ') value.remove_prefix(1);
    while (!value.empty() && static_cast<unsigned char>(value.back()) <= ' ') value.remove_suffix(1);
    return value;
}
std::optional<uint64_t> number(std::string_view value) {
    if (value.empty()) return {};
    uint64_t result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return {};
    return result;
}
std::optional<std::string> read_bounded(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::string text(text_limit + 1, '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (input.bad() || input.gcount() > static_cast<std::streamsize>(text_limit)) return {};
    text.resize(static_cast<size_t>(input.gcount()));
    return text;
}
std::optional<std::string> read(const HostOverviewOptions& options, const char* name) {
    try {
        auto text = options.read_file((std::filesystem::path(options.proc_directory) / name).string());
        if (!text || text->size() > text_limit || text->find('\0') != std::string::npos) return {};
        return text;
    } catch (const std::exception&) { return {}; }
}
std::optional<std::array<uint64_t, 8>> cpu_ticks(const std::string& text) {
    auto line = trim(std::string_view(text).substr(0, text.find('\n')));
    if (!line.starts_with("cpu") || line.size() < 4 || (line[3] != ' ' && line[3] != '\t')) return {};
    line = trim(line.substr(3));
    std::array<uint64_t, 8> ticks{};
    size_t count = 0;
    while (!line.empty()) {
        const auto end = line.find_first_of(" \t\r");
        const auto value = number(line.substr(0, end));
        if (!value || count >= 32) return {};
        if (count < ticks.size()) ticks[count] = *value;
        ++count;
        if (end == std::string_view::npos) break;
        line = trim(line.substr(end));
    }
    // user/nice already include guest/guest_nice. Never add fields 9 and 10.
    return count >= 4 ? std::optional(ticks) : std::nullopt;
}
std::optional<uint32_t> cpu_count(const std::string& text) {
    std::set<uint32_t> ids;
    std::string_view remaining(text);
    while (!remaining.empty()) {
        const auto end = remaining.find('\n');
        const auto line = trim(remaining.substr(0, end));
        if (line.starts_with("cpu") && line.size() > 3 && line[3] != ' ' && line[3] != '\t') {
            const auto split = line.find_first_of(" \t", 3);
            if (split == std::string_view::npos) return {};
            const auto id = number(line.substr(3, split - 3));
            if (!id || *id > std::numeric_limits<uint32_t>::max() || ids.size() >= 4096 ||
                !ids.insert(static_cast<uint32_t>(*id)).second ||
                !cpu_ticks("cpu" + std::string(line.substr(split)))) return {};
        }
        if (end == std::string_view::npos) break;
        remaining.remove_prefix(end + 1);
    }
    // /proc/stat lists online logical CPUs, unlike the full sysfs topology.
    return ids.empty() ? std::nullopt : std::optional(static_cast<uint32_t>(ids.size()));
}
HostOverviewMemory memory(const std::string& text) {
    HostOverviewMemory result;
    bool total_seen = false, available_seen = false;
    std::string_view remaining(text);
    while (!remaining.empty()) {
        const auto end = remaining.find('\n');
        auto line = remaining.substr(0, end);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos) {
            const auto key = line.substr(0, colon);
            if (key == "MemTotal" || key == "MemAvailable") {
                auto& seen = key == "MemTotal" ? total_seen : available_seen;
                auto& value = key == "MemTotal" ? result.total_bytes : result.available_bytes;
                if (seen) value.reset();
                else {
                    line = trim(line.substr(colon + 1));
                    const auto unit = line.find_first_of(" \t");
                    const auto kb = number(line.substr(0, unit));
                    if (kb && unit != std::string_view::npos && trim(line.substr(unit)) == "kB" &&
                        *kb <= std::numeric_limits<uint64_t>::max() / 1024) value = *kb * 1024;
                }
                seen = true;
            }
        }
        if (end == std::string_view::npos) break;
        remaining.remove_prefix(end + 1);
    }
    if (result.total_bytes == 0) result.total_bytes.reset();
    if (result.total_bytes && result.available_bytes && *result.available_bytes > *result.total_bytes)
        result.available_bytes.reset();
    return result;
}
HostOverviewStorage filesystem_space(const std::string& path) {
    // std::filesystem::space uses statvfs on POSIX: capacity=f_blocks*frsize,
    // free=f_bfree*frsize, available=f_bavail*frsize. This is the filesystem
    // containing daemon data, not the sum of VM disk image virtual sizes.
    std::error_code error;
    const auto space = std::filesystem::space(path, error);
    if (error) return {};
    auto known = [](uintmax_t value) -> std::optional<uint64_t> {
        if (value == std::numeric_limits<uintmax_t>::max() || value > std::numeric_limits<uint64_t>::max()) return {};
        return static_cast<uint64_t>(value);
    };
    HostOverviewStorage result{known(space.capacity), known(space.free), known(space.available)};
    if (result.total_bytes && result.free_bytes && *result.free_bytes > *result.total_bytes) result.free_bytes.reset();
    if (result.available_bytes && ((result.free_bytes && *result.available_bytes > *result.free_bytes) ||
        (result.total_bytes && *result.available_bytes > *result.total_bytes))) result.available_bytes.reset();
    return result;
}
}
HostOverviewService::HostOverviewService(HostOverviewOptions options) : options_(std::move(options)) {
    if (options_.data_directory.empty()) throw std::invalid_argument("Host overview requires a data directory");
    if (!options_.read_file) options_.read_file = read_bounded;
    if (!options_.storage) options_.storage = filesystem_space;
    if (!options_.monotonic) options_.monotonic = Clock::now;
    if (!options_.wall_ms) options_.wall_ms = [] {
        const auto count = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return count < 0 ? uint64_t(0) : static_cast<uint64_t>(count);
    };
    if (options_.daemon.pid <= 0) {
#ifdef _WIN32
        options_.daemon.pid = _getpid();
#else
        options_.daemon.pid = getpid();
#endif
    }
#ifndef _WIN32
    utsname host{};
    if (uname(&host) == 0) {
        if (!options_.host.kernel_release) options_.host.kernel_release = host.release;
        if (!options_.host.machine) options_.host.machine = host.machine;
    }
#endif
}
HostOverview HostOverviewService::snapshot() {
    std::lock_guard lock(mutex_);
    const auto now = options_.monotonic();
    if (cached_ && now >= cached_at_ && now - cached_at_ < std::chrono::seconds(1)) return *cached_;
    HostOverview result;
    result.observed_at_ms = options_.wall_ms();
    result.host = options_.host; result.daemon = options_.daemon;
    if (const auto contents = read(options_, "stat")) {
        result.cpu.logical_count = cpu_count(*contents);
        if (const auto ticks = cpu_ticks(*contents)) {
            CpuSample current{*ticks, now};
            if (previous_cpu_ && now > previous_cpu_->at && now - previous_cpu_->at <= std::chrono::seconds(30)) {
                uint64_t total = 0, idle = 0;
                bool valid = true;
                for (size_t i = 0; i < ticks->size(); ++i) {
                    if ((*ticks)[i] < previous_cpu_->ticks[i]) { valid = false; break; }
                    const auto delta = (*ticks)[i] - previous_cpu_->ticks[i];
                    if (delta > std::numeric_limits<uint64_t>::max() - total) { valid = false; break; }
                    total += delta;
                    if (i == 3 || i == 4) idle += delta; // idle and iowait are not busy CPU.
                }
                if (valid && total > 0 && idle <= total) {
                    result.cpu.usage_percent = static_cast<double>(total - idle) / static_cast<double>(total) * 100.0;
                    result.cpu.sample_window_ms = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(now - previous_cpu_->at).count());
                }
            }
            previous_cpu_ = std::move(current);
        } else previous_cpu_.reset();
    } else previous_cpu_.reset();
    if (const auto contents = read(options_, "meminfo")) result.memory = memory(*contents);
    try { result.storage = options_.storage(options_.data_directory); } catch (const std::exception&) {}
    cached_ = result; cached_at_ = now;
    return result;
}

struct HostDiskCapacity::Shared {
    using Clock = std::chrono::steady_clock;
    struct Sample { std::optional<uint64_t> bytes; Clock::time_point at; uint64_t wall_ms = 0; };
    std::mutex mutex;
    Inspect inspect;
    Post post;
    std::string revision;
    std::vector<std::string> ids;
    std::map<std::string, Sample> samples;
    uint64_t generation = 0;
    size_t cursor = 0;
    bool pending = false;
    Clock::time_point next_scan{};
};
HostDiskCapacity::HostDiskCapacity(Inspect inspect, Post post) : shared_(std::make_shared<Shared>()) {
    if (!inspect || !post) throw std::invalid_argument("Disk capacity dependencies required");
    shared_->inspect = std::move(inspect); shared_->post = std::move(post);
}
void HostDiskCapacity::schedule(const std::shared_ptr<Shared>& state) {
    std::string id, revision;
    uint64_t generation;
    {
        std::lock_guard lock(state->mutex);
        if (state->pending || state->cursor >= state->ids.size()) return;
        id = state->ids[state->cursor++]; revision = state->revision; generation = state->generation;
        state->pending = true;
    }
    try {
        state->post([state, id, revision, generation](bool discarded) {
            std::optional<uint64_t> bytes;
            if (!discarded) try { bytes = state->inspect(id, revision); } catch (const std::exception&) {}
            bool again = false;
            {
                std::lock_guard lock(state->mutex);
                state->pending = false;
                if (generation == state->generation && !discarded) {
                    const auto wall = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    state->samples[id] = {bytes, Shared::Clock::now(), wall < 0 ? 0 : static_cast<uint64_t>(wall)};
                }
                if (!discarded) again = state->cursor < state->ids.size();
                if (!again) state->next_scan = Shared::Clock::now() + std::chrono::seconds(30);
            }
            if (again) schedule(state);
        });
    } catch (const std::exception&) {
        std::lock_guard lock(state->mutex);
        state->pending = false;
        // Queue saturation is not a disk result. Retry a new round on a later GET.
        state->cursor = state->ids.size();
        state->next_scan = Shared::Clock::now() + std::chrono::seconds(5);
    }
}
HostDiskCapacityView HostDiskCapacity::read(std::string revision, std::vector<std::string> ids) {
    if (revision.empty() || revision.size() > 256 || ids.size() > 4096) return {};
    std::sort(ids.begin(), ids.end());
    if (std::adjacent_find(ids.begin(), ids.end()) != ids.end() ||
        std::any_of(ids.begin(), ids.end(), [](const auto& id) { return id.empty() || id.size() > 128; })) return {};
    HostDiskCapacityView result;
    {
        std::lock_guard lock(shared_->mutex);
        const auto now = Shared::Clock::now();
        if (shared_->revision != revision || shared_->ids != ids) {
            shared_->revision = std::move(revision); shared_->ids = std::move(ids);
            shared_->samples.clear(); shared_->cursor = 0; ++shared_->generation;
            shared_->next_scan = {};
        } else if (!shared_->pending && shared_->cursor >= shared_->ids.size() && now >= shared_->next_scan) {
            shared_->cursor = 0;
        }
        uint64_t total = 0;
        bool overflow = false;
        for (const auto& [id, sample] : shared_->samples) {
            (void)id;
            if (!sample.bytes || now < sample.at || now - sample.at > std::chrono::seconds(60)) continue;
            ++result.known_count;
            if (*sample.bytes > std::numeric_limits<uint64_t>::max() - total) overflow = true;
            else total += *sample.bytes;
            result.observed_at_ms = result.observed_at_ms ? std::min(*result.observed_at_ms, sample.wall_ms) : sample.wall_ms;
        }
        if (!overflow && result.known_count == shared_->ids.size()) result.total_bytes = total;
    }
    schedule(shared_);
    return result;
}

}
