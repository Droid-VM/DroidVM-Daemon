// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <string>

namespace droidvm::vm {
// Host reads stay with the caller. hypervisor is the existing resolver's concrete
// default; soc_model is the raw SoC identifier, not its marketing name.
Json::Value new_vm_defaults(const std::string& data_dir, const std::string& hypervisor,
                           const std::string& soc_model);
}
