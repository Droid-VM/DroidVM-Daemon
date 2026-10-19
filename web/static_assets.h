// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <span>
#include <string_view>

namespace droidvm::web {
// Immutable, build-generated resources. No request path ever reaches a filesystem.
struct StaticAsset {
    std::string_view path, type, etag, body, gzip;
};
std::span<const StaticAsset> embedded_assets();
}
