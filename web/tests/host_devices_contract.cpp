// SPDX-License-Identifier: GPL-3.0-or-later
#include "web/resource_catalog.h"
#include "services/context.h"
#include "common/identity.h"
#include "common/wire.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <source_location>

namespace fs = std::filesystem;
void require(bool value, const std::source_location& at = std::source_location::current()) {
    if (!value) throw std::runtime_error("Host device contract failed at line " + std::to_string(at.line()));
}
void touch(const fs::path& path) { fs::create_directories(path.parent_path()); std::ofstream(path) << "fixture"; }
int main() {
    const auto root = fs::temp_directory_path() / ("droidvm-host-" + droidvm::random_id(true));
    try {
        fs::create_directories(root);
        const auto read = [&] { return droidvm::vm::probe_host_devices(root.string(), (root / "dev").string(), (root / "hal").string()); };
        auto facts = read();
        require(facts.kvm == false && facts.turnip == false && facts.system_vulkan == false);
        touch(root / "dev/kvm"); touch(root / "dev/kgsl-3d0");
        touch(root / "usr/lib/libvulkan_freedreno.so");
        touch(root / "hal/vulkan.swiftshader.so"); touch(root / "hal/vulkan.lvp.so");
        require(read().system_vulkan == false);
        fs::create_directories(root / "hal/vulkan.directory.so");
        require(read().system_vulkan == false);
        touch(root / "hal/vulkan.vendor.so");
        facts = read();
        require(facts.kvm == true && facts.kgsl == true && facts.turnip == true && facts.system_vulkan == true);
        require(facts.system_vulkan_hal.has_value() &&
            fs::equivalent(*facts.system_vulkan_hal, root / "hal/vulkan.vendor.so"));
        const auto observed = droidvm::web::host_device_catalog(facts, droidvm::wire::parse(R"({"state":"known","missingExtensions":[],"checkedAtMs":1,"private":"omit"})"));
        require(observed["devices"]["turnip"].asBool() && observed["systemBlit"]["missingExtensions"].empty());
        require(!observed["systemBlit"].isMember("private") && !observed["devices"].isMember("system_vulkan_hal"));
        const auto unknown = droidvm::web::host_device_catalog({}, droidvm::wire::parse(R"({"state":"unknown","missingExtensions":null,"checkedAtMs":1})"));
        require(unknown["devices"]["kvm"].isNull() && unknown["systemBlit"]["missingExtensions"].isNull());
        bool rejected = false;
        try { (void)droidvm::web::host_device_catalog(facts, droidvm::wire::parse(R"({"state":"known","missingExtensions":null,"checkedAtMs":1})")); }
        catch (const droidvm::ServiceError&) { rejected = true; }
        require(rejected);
        fs::remove_all(root);
        std::cout << "Host metadata, software-driver exclusions and bounded projection contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        fs::remove_all(root); std::cerr << error.what() << '\n'; return 1;
    }
}
