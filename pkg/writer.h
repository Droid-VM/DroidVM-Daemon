// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "format.h"
#include "tar.h"
#include <functional>
#include <string>

namespace droidvm::pkg {
// VMExportTask.startWriteSingle / startWriteSplit for a finished manifest.
struct PackageSpec {
    std::string dest;
    int64_t volume_size = 0; // <= 0: one self-contained file
    Compression compression = Compression::zstd;
    int manifest_version = manifest_version_base;
    int app_version_code = 0;
    // The sub-volume set while the data is written, then null.
    std::function<void(const VolumeSplitSink*)> splitting = [](const VolumeSplitSink*) {};
};
// "manifest too large: N bytes" past the 16-bit header field.
std::string manifest_text(const Manifest& manifest);
// The tar holds manifest.json, then whatever pack adds. Returns the number
// of sub-volumes, 0 for a single file. A failed split removes its sub-volumes.
int write_package(const PackageSpec& spec, const std::string& manifest_bytes, const std::function<void(TarWriter& tar)>& pack);
}
