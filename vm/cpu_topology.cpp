// SPDX-License-Identifier: GPL-3.0-or-later
#include "cpu_topology.h"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace droidvm::vm {
namespace {
std::string_view trim(std::string_view text) {
    while (!text.empty() && static_cast<unsigned char>(text.front()) <= ' ') text.remove_prefix(1);
    while (!text.empty() && static_cast<unsigned char>(text.back()) <= ' ') text.remove_suffix(1);
    return text;
}
std::optional<std::string> read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::string text(65537, '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (input.bad() || input.gcount() > 65536) return {};
    text.resize(static_cast<size_t>(input.gcount()));
    return text;
}
std::optional<int64_t> integer(std::string_view text) {
    text = trim(text);
    if (!text.empty() && text.front() == '+') text.remove_prefix(1);
    if (text.empty()) return {};
    int64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) return {};
    return value;
}
int64_t number(const std::filesystem::path& path) {
    const auto raw = read(path);
    return raw ? integer(*raw).value_or(0) : 0;
}
using Ranges = std::vector<std::pair<int, int>>;
std::optional<Ranges> online_ranges(const std::filesystem::path& path) {
    const auto raw = read(path);
    if (!raw) return {};
    auto text = trim(*raw);
    Ranges ranges;
    while (!text.empty()) {
        const auto comma = text.find(',');
        const auto part = text.substr(0, comma);
        const auto dash = part.find('-');
        const auto first = integer(part.substr(0, dash));
        const auto last = dash == std::string_view::npos ? first : integer(part.substr(dash + 1));
        if (!first || !last || *first < 0 || *last < *first || *last > std::numeric_limits<int>::max()) return {};
        ranges.emplace_back(static_cast<int>(*first), static_cast<int>(*last));
        if (comma == std::string_view::npos) break;
        text.remove_prefix(comma + 1);
        if (text.empty()) return {};
    }
    return ranges;
}
}
std::vector<HostCpuCore> read_cpu_topology(const std::string& root, int fallback_count) {
    namespace fs = std::filesystem;
    std::vector<int> indices;
    std::error_code error;
    fs::directory_iterator cursor(root, error), end;
    size_t entries = 0;
    while (!error && cursor != end) {
        if (++entries > 16384) throw std::length_error("CPU directory too large");
        const auto name = cursor->path().filename().string();
        if (name.size() > 3 && name.starts_with("cpu") &&
            std::all_of(name.begin() + 3, name.end(), [](char ch) { return ch >= '0' && ch <= '9'; })) {
            const auto index = integer(std::string_view(name).substr(3));
            std::error_code type_error;
            if (index && *index <= std::numeric_limits<int>::max() && cursor->is_directory(type_error))
                indices.push_back(static_cast<int>(*index));
        }
        cursor.increment(error);
    }
    // A failed enumeration must not look like a complete catalogue.
    if (error) indices.clear();
    if (indices.empty()) {
        if (fallback_count > 4096) throw std::length_error("CPU count too large");
        for (int i = 0; i < fallback_count; ++i) indices.push_back(i);
    }
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
    if (indices.size() > 4096) throw std::length_error("CPU count too large");
    const auto online = online_ranges(fs::path(root) / "online");
    std::vector<HostCpuCore> result;
    int64_t fastest = 0;
    for (const auto index : indices) {
        const auto path = fs::path(root) / ("cpu" + std::to_string(index));
        HostCpuCore core{index, 0, 0, false, {}};
        core.max_frequency_khz = number(path / "cpufreq/cpuinfo_max_freq");
        if (core.max_frequency_khz <= 0) core.max_frequency_khz = number(path / "cpufreq/scaling_max_freq");
        core.capacity = number(path / "cpu_capacity");
        if (online) core.online = std::any_of(online->begin(), online->end(), [index](const auto& range) {
            return range.first <= index && index <= range.second;
        });
        else if (const auto raw = read(path / "online")) {
            const auto value = integer(*raw);
            if (value == 0 || value == 1) core.online = *value == 1;
        }
        fastest = std::max(fastest, core.max_frequency_khz);
        result.push_back(core);
    }
    for (auto& core : result) {
        if (core.capacity <= 0 && core.max_frequency_khz > 0 && fastest > 0) {
            core.capacity = std::max<int64_t>(1, std::llround(1024.0 * static_cast<double>(core.max_frequency_khz) / static_cast<double>(fastest)));
            core.capacity_estimated = true;
        }
    }
    return result;
}
}
