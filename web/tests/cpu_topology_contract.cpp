// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/resource_catalog.h"
#include "common/identity.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
void require(bool value) { if (!value) throw std::runtime_error("CPU topology contract failed"); }
void write(const fs::path& path, const std::string& value) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << value;
}
int main() {
    const auto root = fs::temp_directory_path() / ("droidvm-cpu-" + droidvm::random_id(true));
    try {
        fs::create_directories(root);
        require(droidvm::vm::read_cpu_topology(root.string()).empty());
        const auto fallback = droidvm::vm::read_cpu_topology(root.string(), 2);
        require(fallback.size() == 2 && fallback[0].index == 0 && fallback[1].index == 1 && !fallback[0].online);
        write(root / "online", "0,4\n");
        write(root / "cpu0/cpufreq/cpuinfo_max_freq", "1800000\n");
        write(root / "cpu0/cpu_capacity", "600\n");
        write(root / "cpu4/cpufreq/cpuinfo_max_freq", "invalid");
        write(root / "cpu4/cpufreq/scaling_max_freq", "3600000\n");
        fs::create_directories(root / "cpu7");
        write(root / "cpu-1/cpu_capacity", "1000");
        write(root / "cpu999999999999999999999/cpu_capacity", "1000");
        auto cores = droidvm::vm::read_cpu_topology(root.string());
        require(cores.size() == 3 && cores[1].index == 4 && cores[2].index == 7);
        require(cores[0].capacity == 600 && !cores[0].capacity_estimated && cores[0].online == true);
        require(cores[1].max_frequency_khz == 3600000 && cores[1].capacity == 1024 && cores[1].capacity_estimated);
        require(cores[2].online == false && cores[2].capacity == 0);
        const auto projected = droidvm::web::cpu_catalog(cores);
        require(projected["items"][2]["maxFrequencyKHz"].isNull() && projected["items"][2]["capacity"].isNull());
        write(root / "online", "0-2147483647");
        require(droidvm::vm::read_cpu_topology(root.string())[2].online == true);
        write(root / "online", "broken");
        write(root / "cpu4/online", "0");
        write(root / "cpu0/cpu_capacity", "0");
        cores = droidvm::vm::read_cpu_topology(root.string());
        require(!cores[0].online && cores[1].online == false && !cores[2].online);
        require(cores[0].capacity == 512 && cores[0].capacity_estimated);
        write(root / "cpu4/cpufreq/scaling_max_freq", std::string(65537, '9'));
        require(droidvm::vm::read_cpu_topology(root.string())[1].max_frequency_khz == 0);
        fs::remove_all(root);
        std::cout << "CPU sysfs, fallback, online, frequency/capacity and projection contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        fs::remove_all(root);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
