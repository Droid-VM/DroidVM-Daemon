// SPDX-License-Identifier: GPL-3.0-or-later
#include "defaults.h"
#include "common/wire.h"
#include "common/identity.h"
#include "vm_defaults_data.h"
#include <chrono>
#include <cctype>
#include <stdexcept>

namespace droidvm::vm {
Json::Value new_vm_defaults(const std::string& data_dir, const std::string& hypervisor,
                           const std::string& soc_model) {
    if (data_dir.empty() || data_dir.front() != '/' ||
        (hypervisor != "KVM" && hypervisor != "GUNYAH" && hypervisor != "GENIEZONE"))
        throw std::invalid_argument("Invalid new VM host defaults");
    static const auto defaults = wire::parse(vm_defaults_json);
    static const auto table = wire::parse(gunyah_json);
    auto row = defaults;
    row["id"] = random_id(true);
    row["name"] = ""; // The client supplies the localized, unique name before saving.
    row["created_at"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    std::string selected = hypervisor;
    for (auto& ch : selected) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    row["hypervisor"] = selected;
    row["protected_vm"] = hypervisor == "GUNYAH" ? "pseudo_unprotected" : "protected_normal";
    std::string root = data_dir;
    while (root.size() > 1 && root.back() == '/') root.pop_back();
    row["boot"]["linux"]["kernel"] = root + "/usr/share/droidvm/vmlinuz";
    row["boot"]["linux"]["initrd"] = root + "/usr/share/droidvm/initramfs.img";
    std::string soc = soc_model;
    while (!soc.empty() && static_cast<unsigned char>(soc.back()) <= ' ') soc.pop_back();
    const auto start = soc.find_first_not_of(" \t\r\n\f\v");
    soc = start == std::string::npos ? "" : soc.substr(start);
    for (auto& ch : soc) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    Json::Value capabilities;
    for (const auto& entry : table["gunyah"])
        for (const auto& model : entry["socs"])
            if (model.asString() == soc) capabilities = entry["capabilities"];
    row["prepare_lend_mthp"] = "chunked";
    for (const auto& [flag, mode] : {std::pair{"no_mthp", "disabled"},
            std::pair{"mthp_chunked", "chunked"}, std::pair{"mthp_single", "single"}})
        if (capabilities.get(flag, false).asBool()) row["prepare_lend_mthp"] = mode;
    return row;
}
}
