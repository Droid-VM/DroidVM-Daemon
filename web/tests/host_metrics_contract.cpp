// SPDX-License-Identifier: GPL-3.0-or-later
#include "services/host_overview.h"
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <deque>
#include <limits>

using namespace droidvm;
namespace {
namespace fs = std::filesystem;
void require(bool value) { if (!value) throw std::runtime_error("Host metrics contract failed"); }
struct Fixture {
    fs::path root = fs::temp_directory_path() / ("droidvm-host-metrics-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::chrono::steady_clock::time_point now{};
    uint64_t wall = 1000;
    unsigned space_reads = 0;
    bool fail_space = false;
    Fixture() { require(fs::create_directory(root)); }
    ~Fixture() { std::error_code error; fs::remove_all(root, error); }
    void file(const char* name, const std::string& value) {
        std::ofstream output(root / name, std::ios::binary | std::ios::trunc);
        output << value; output.close(); require(output.good());
    }
    void ticks(uint64_t user, uint64_t idle, uint64_t guest = 0) {
        file("stat", "cpu " + std::to_string(user) + " 0 0 " + std::to_string(idle) + " 0 0 0 0 " +
            std::to_string(guest) + " 0\ncpu0 0 0 0 0 0 0 0 0\ncpu1 0 0 0 0 0 0 0 0\nintr 0\n");
    }
    void advance(uint64_t milliseconds = 1000) {
        now += std::chrono::milliseconds(milliseconds); wall += milliseconds;
    }
    HostOverviewOptions options() {
        HostOverviewOptions options;
        options.data_directory = root.string(); options.proc_directory = root.string();
        options.daemon = {123, "fixture-version"};
        options.host = {"fixture-kernel", "fixture-machine", "fixture-device", "fixture-soc"};
        options.monotonic = [&] { return now; }; options.wall_ms = [&] { return wall; };
        options.storage = [&](const std::string& path) {
            require(path == root.string()); ++space_reads;
            if (fail_space) throw std::runtime_error("Filesystem unavailable");
            return HostOverviewStorage{4096, 1024, 512};
        };
        return options;
    }
};
void samples_and_unknowns() {
    Fixture fixture;
    fixture.ticks(100, 100, 40);
    fixture.file("meminfo", "MemTotal: 8192 kB\nMemAvailable: 3072 kB\nMemFree: 2048 kB\n");
    HostOverviewService service(fixture.options());
    auto first = service.snapshot();
    require(first.observed_at_ms == 1000 && first.daemon.pid == 123 && first.daemon.version == "fixture-version");
    require(first.host.soc_model == "fixture-soc" && first.cpu.logical_count == 2);
    require(!first.cpu.usage_percent && !first.cpu.sample_window_ms);
    require(first.memory.total_bytes == 8192u * 1024 && first.memory.available_bytes == 3072u * 1024);
    require(first.storage.total_bytes == 4096 && first.storage.free_bytes == 1024 && first.storage.available_bytes == 512);
    fixture.ticks(130, 130, 70); fixture.advance(500);
    require(service.snapshot().observed_at_ms == 1000 && fixture.space_reads == 1);
    fixture.advance(500);
    auto measured = service.snapshot();
    require(measured.cpu.usage_percent && std::abs(*measured.cpu.usage_percent - 50.0) < 0.00001);
    require(measured.cpu.sample_window_ms == 1000 && fixture.space_reads == 2); // guest not counted twice.
    fixture.ticks(5, 5); fixture.advance();
    require(!service.snapshot().cpu.usage_percent); // counter rollback establishes a new baseline.
    fixture.ticks(15, 15); fixture.advance();
    require(service.snapshot().cpu.usage_percent == 50.0);
    fixture.ticks(30, 30); fixture.advance(31000);
    require(!service.snapshot().cpu.usage_percent); // a stale browser does not get a 31s average.
    fixture.ticks(40, 40); fixture.advance();
    require(service.snapshot().cpu.usage_percent == 50.0);
    fixture.file("meminfo", "MemTotal: 8192 kB\nMemFree: 2048 kB\n");
    fixture.file("stat", "cpu 50 0 0 50\ncpu0 1 0 0 1\ncpu0 1 0 0 1\n");
    fixture.advance(); measured = service.snapshot();
    require(!measured.memory.available_bytes && !measured.cpu.logical_count); // no MemFree substitution or duplicate CPUs.
    fixture.file("meminfo", "MemTotal: 18446744073709551615 kB\nMemAvailable: -3 kB\n");
    fixture.file("stat", "cpu broken\n"); fixture.fail_space = true;
    fixture.advance(); measured = service.snapshot();
    require(!measured.memory.total_bytes && !measured.memory.available_bytes && !measured.cpu.usage_percent && !measured.storage.total_bytes);
    fixture.ticks(60, 60); fixture.advance();
    require(!service.snapshot().cpu.usage_percent); // a failed sample resets rather than reusing old data.
    fixture.ticks(70, 70); fixture.advance();
    require(service.snapshot().cpu.usage_percent == 50.0);
    fixture.now -= std::chrono::seconds(2);
    require(!service.snapshot().cpu.usage_percent); // monotonic clock rollback cannot produce negative windows.
}
void real_space_and_bounded_files() {
    Fixture fixture;
    auto options = fixture.options(); options.storage = {};
    HostOverviewService service(std::move(options));
    auto observed = service.snapshot();
    const auto actual = fs::space(fixture.root);
    require(observed.storage.total_bytes == actual.capacity && observed.storage.free_bytes && observed.storage.available_bytes);
    require(!observed.memory.total_bytes && !observed.cpu.usage_percent && !observed.cpu.logical_count);
    fixture.file("stat", std::string(65537, 'x'));
    fixture.file("meminfo", "MemTotal: 1024 kB\nMemTotal: 2048 kB\nMemAvailable: 3000 kB\n");
    fixture.advance(); observed = service.snapshot();
    require(!observed.cpu.logical_count && !observed.memory.total_bytes);
    fixture.file("meminfo", "MemTotal: 1024 kB\nMemAvailable: 3000 kB\n");
    fixture.advance(); require(!service.snapshot().memory.available_bytes);
}
void bounded_disk_capacity() {
    std::deque<std::function<void(bool)>> work;
    size_t reads = 0;
    bool unavailable = false;
    HostDiskCapacity capacity([&](const std::string& id, const std::string&) -> std::optional<uint64_t> {
        ++reads;
        if (unavailable && id == "b") return {};
        return id == "a" ? 1024 : 2048;
    }, [&](auto next) { work.push_back(std::move(next)); });
    auto drain = [&] { while (!work.empty()) { auto next = std::move(work.front()); work.pop_front(); next(false); } };
    auto first = capacity.read("r1", {"a", "b"});
    require(!first.total_bytes && first.known_count == 0 && reads == 0 && work.size() == 1);
    auto next = std::move(work.front()); work.pop_front(); next(false);
    require(reads == 1 && work.size() == 1);
    auto partial = capacity.read("r1", {"a", "b"});
    require(!partial.total_bytes && partial.known_count == 1);
    drain();
    auto complete = capacity.read("r1", {"a", "b"});
    require(complete.total_bytes == 3072 && complete.known_count == 2 && complete.observed_at_ms);
    unavailable = true;
    require(!capacity.read("r2", {"a", "b"}).total_bytes);
    drain();
    require(!capacity.read("r2", {"a", "b"}).total_bytes && capacity.read("r2", {"a", "b"}).known_count == 1);
    capacity.read("r3", {"a", "b"});
    capacity.read("r4", {}); // in-flight old results must not reappear in a new inventory.
    drain();
    require(capacity.read("r4", {}).total_bytes == 0);
    HostDiskCapacity overflow([](const auto&, const auto&) { return std::optional<uint64_t>(std::numeric_limits<uint64_t>::max()); },
        [&](auto next_work) { work.push_back(std::move(next_work)); });
    overflow.read("overflow", {"a", "b"}); drain();
    require(!overflow.read("overflow", {"a", "b"}).total_bytes);
}
}
int main() {
    try {
        samples_and_unknowns(); std::cout << "PASS request-driven CPU and memory observations\n";
        real_space_and_bounded_files(); std::cout << "PASS real data filesystem and bounded unavailable reads\n";
        bounded_disk_capacity(); std::cout << "PASS bounded asynchronous disk capacity and revision changes\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
