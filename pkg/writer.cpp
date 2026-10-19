// SPDX-License-Identifier: GPL-3.0-or-later
#include "writer.h"
#include <unistd.h>

namespace droidvm::pkg {
std::string manifest_text(const Manifest& manifest) {
    auto bytes = java_json(manifest.json(), 4);
    if (bytes.size() > 0xffff) throw Error("manifest too large: " + std::to_string(bytes.size()) + " bytes");
    return bytes;
}
namespace {
void stream(Sink& out, Compression compression, const std::string& manifest_bytes, const std::function<void(TarWriter&)>& pack) {
    auto encoder = compress(out, compression);
    TarWriter tar(*encoder);
    tar.entry(manifest_name, manifest_bytes);
    pack(tar);
    tar.close();
    encoder->finish();
}
void head(FileSink& out, const std::string& manifest_bytes) {
    write_zero(out, header_size);
    write_zero(out, align_up(out.position()) - out.position());
    out.append(manifest_bytes);
    write_zero(out, align_up_strict(out.position()) - out.position());
}
}
int write_package(const PackageSpec& spec, const std::string& manifest_bytes, const std::function<void(TarWriter&)>& pack) {
    if (spec.volume_size <= 0) {
        FileSink out(spec.dest);
        head(out, manifest_bytes);
        const auto start = out.position();
        stream(out, spec.compression, manifest_bytes, pack);
        const auto end = out.position();
        write_zero(out, align_up(end) - end);
        const auto header = Header::build(spec.manifest_version, spec.app_version_code, manifest_bytes.size(), spec.compression,
                                          static_cast<int64_t>(end - start), 0);
        out.write_at(0, std::string_view(header.data(), header.size()));
        if (spec.completed_file) { out.flush(); spec.completed_file(spec.dest, out.fd()); }
        out.close();
        return 0;
    }
    // Sub-volumes first, then the metadata master at the picked path.
    VolumeSplitSink volumes(spec.dest, spec.volume_size, spec.completed_file);
    spec.splitting(&volumes);
    try {
        stream(volumes, spec.compression, manifest_bytes, pack);
        volumes.finish();
    } catch (...) {
        spec.splitting(nullptr);
        volumes.abort();
        for (const auto& file : volumes.files()) unlink(file.c_str());
        throw;
    }
    spec.splitting(nullptr);
    const auto count = volumes.volume_count();
    VolumeIndex index;
    index.data_size = volumes.data_size();
    index.volumes = volumes.entries();
    FileSink out(spec.dest);
    head(out, manifest_bytes);
    out.append(index.json());
    const auto header = Header::build(spec.manifest_version, spec.app_version_code, manifest_bytes.size(), spec.compression,
                                      index.data_size, count);
    out.write_at(0, std::string_view(header.data(), header.size()));
    if (spec.completed_file) { out.flush(); spec.completed_file(spec.dest, out.fd()); }
    out.close();
    // Drop higher-numbered sub-volumes left by an earlier, larger export.
    for (int i = count + 1; i <= volume_max_count; ++i) {
        const auto stale = volume_name(spec.dest, i);
        if (!exists(stale)) break;
        unlink(stale.c_str());
    }
    return count;
}
}
