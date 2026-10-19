// SPDX-License-Identifier: GPL-3.0-or-later
#include "services/network.h"
#include "common/identity.h"
#include "common/fd.h"
#include "common/wire.h"
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <source_location>
#include <unistd.h>
using namespace droidvm;
namespace {
const CallContext caller{"network-contract", true, true, true};
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Network lifecycle contract failed at line " + std::to_string(at.line()));
}
template<class Work> void rejected(ErrorCode code, Work work) {
    try { work(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected lifecycle rejection");
}
struct Temporary {
    std::filesystem::path path;
    Fd directory;
    explicit Temporary(const char* root) : path(std::filesystem::path(root) / ("droidvm-network-lifecycle-" + random_id(false))) {
        require(std::filesystem::create_directory(path));
        directory = Fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        require(directory.get() >= 0);
    }
    ~Temporary() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
};
struct Backend final : network::Backend {
    bool running = false;
    bool* fail_stop;
    std::function<void()> on_start;
    Json::Value leases;
    Backend(bool& fail, std::function<void()> start) : fail_stop(&fail), on_start(std::move(start)) {}
    void start(const Json::Value&) override { on_start(); running = true; }
    bool healthy() const override { return running; }
    void recover(const Json::Value& config) override { start(config); }
    void stop() override { if (*fail_stop) throw std::runtime_error("injected cleanup failure"); running = false; }
    void attach(const Json::Value&, const std::string&) override {}
    Json::Value dhcp_leases() const override { return leases; }
};
}
int main(int argc, char** argv) {
    try {
        // Only a caller-selected temporary directory is touched. A gvisor
        // configuration plus memory Backend never creates real interfaces,
        // launches processes, or acquires host forwarding demand.
        if (argc != 2) throw std::runtime_error("usage: network_lifecycle_contract <temporary-directory>");
        Temporary temp(argv[1]);
        auto gate = std::make_shared<ConfigurationGate>();
        NetworkConfigService configs(temp.directory.get(), getuid(), {}, nullptr, false, gate);
        auto config = wire::parse(R"({"schema":2,"name":"conditional","bridge_name":"test","bridge_type":"gvisor","l3":{"vlans":[]}})");
        config["id"] = random_id(true);
        const auto id = configs.create(caller, config);
        bool fail_stop = false;
        int starts = 0;
        auto now = NetworkService::Clock::now();
        Backend* backend = nullptr;
        NetworkService service(configs, [&](const Json::Value&) {
            auto result = std::make_unique<Backend>(fail_stop, [&] {
                ++starts;
                rejected(ErrorCode::conflict, [&] { configs.update(caller, config); });
            });
            backend = result.get(); return result;
        }, [&] { return now; });
        const auto first = configs.get_with_revision(caller, id);
        config["name"] = "edited"; configs.update(caller, config);
        rejected(ErrorCode::conflict, [&] { service.change_if_matches(caller, id, true, 0, NetworkState::stopped, first.revision); });
        require(starts == 0 && service.get(caller, id).generation == 0);
        auto revision = configs.get_with_revision(caller, id).revision;
        rejected(ErrorCode::conflict, [&] { service.change_if_matches(caller, id, true, 1, NetworkState::stopped, revision); });
        rejected(ErrorCode::conflict, [&] { service.change_if_matches(caller, id, true, 0, NetworkState::running, revision); });
        auto view = service.change_if_matches(caller, id, true, 0, NetworkState::stopped, revision);
        require(view.state == NetworkState::running && starts == 1);
        require(service.observed_leases(caller, id).isNull());
        backend->leases = wire::parse(R"([{"mac":"02:AA:BB:CC:DD:EE","ip":"192.0.2.7","vlan":7,"expires":9223372036854775807},{"mac":"02:aa:bb:cc:dd:ee","ip":"not-an-ip","vlan":7,"expires":9223372036854775807}])");
        now += std::chrono::seconds(5); service.reconcile(caller, id);
        const auto observed = service.observed_leases(caller, id);
        require(observed.size() == 1 && observed[0]["mac"] == "02:aa:bb:cc:dd:ee");
        require(service.get(caller, id).generation == view.generation);
        now += std::chrono::seconds(16);
        require(service.observed_leases(caller, id).isNull());
        backend->leases = Json::Value(); service.reconcile(caller, id);
        require(service.observed_leases(caller, id).isNull() && service.get(caller, id).state == NetworkState::running);
        auto unrelated = config; unrelated["id"] = random_id(true); unrelated["name"] = "unrelated";
        configs.create(caller, unrelated);
        rejected(ErrorCode::conflict, [&] { service.change_if_matches(caller, id, false, view.generation, view.state, revision); });
        revision = configs.get_with_revision(caller, id).revision;
        service.set_in_use([](const std::string&) { return "running VM"; });
        rejected(ErrorCode::conflict, [&] { service.change_if_matches(caller, id, false, view.generation, view.state, revision); });
        // Deterministically reproduce an attachment after the in-use snapshot,
        // before stop takes its operation lock. The callback deliberately
        // returns the old empty answer; the attached-TAP guard still rejects.
        service.set_in_use([&](const std::string&) { service.attach_nic(caller, id, Json::Value(), "test-tap"); return std::string(); });
        rejected(ErrorCode::conflict, [&] { service.change_if_matches(caller, id, false, view.generation, view.state, revision); });
        require(service.get(caller, id).state == NetworkState::running);
        service.set_in_use({});
        service.detach_nic(caller, id, Json::Value(), "test-tap");
        fail_stop = true;
        rejected(ErrorCode::io_error, [&] { service.change_if_matches(caller, id, false, view.generation, view.state, revision); });
        view = service.get(caller, id);
        require(view.state == NetworkState::failed && !view.desired_running);
        rejected(ErrorCode::conflict, [&] { configs.update(caller, config); });
        fail_stop = false;
        { auto transaction = gate->transaction(); transaction.require_recovery(); }
        // Recovery gating must not prevent cleanup of an already-owned runtime.
        view = service.change_if_matches(caller, id, false, view.generation, view.state, revision);
        require(view.state == NetworkState::stopped);
        { auto transaction = gate->transaction(); transaction.recovered(); }
        configs.update(caller, config); // successful cleanup released the lease
        require(service.shutdown().empty());
        std::cout << "network lifecycle contracts passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
