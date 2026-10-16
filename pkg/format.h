// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "compression.h"
#include <json/json.h>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// lib/pkg: the .vmpkg container. A single-file package is
//   [24-byte header][zeros to 4 KiB][manifest][zeros to the next 4 KiB, never none]
//   [compressed tar][zeros to 4 KiB]
// A split package keeps the header, manifest and padding in the master
// followed by the volume index JSON, and the compressed tar in <base>.001...
namespace droidvm::pkg {
inline constexpr const char* extension = "vmpkg";
inline constexpr size_t header_size = 24;
inline constexpr int manifest_version_base = 1;
inline constexpr int manifest_version_backing_chain = 2; // ManifestFeature.BACKING_CHAIN
inline constexpr int manifest_version = manifest_version_backing_chain; // ManifestFeature.latest()
inline constexpr const char* manifest_name = "manifest.json";
inline constexpr int64_t min_volume_size = 16ll * 1024 * 1024;
inline constexpr const char* volume_magic = "VMPV";
inline constexpr int volume_version = 1;
inline constexpr int volume_max_count = 999;
inline const std::vector<const char*> disk_buses{"VIRTIO", "SCSI", "PMEM", "PFLASH", "CDROM"};
inline const std::vector<const char*> disk_formats{"QCOW2", "RAW", "VHDX", "VDI", "VMDK", "ISO"};
std::string disk_format_of(const std::string& filename); // DiskFormat.fromFilename

struct Header {
    int manifest_version = 0, app_version_code = 0, manifest_size = 0, compression = 0, volume_count = 0;
    int64_t data_size = 0;
    static Header parse(const char* bytes); // parseFromData + validate
    static std::array<char, header_size> build(int manifest_version, int app_version_code, size_t manifest_size,
                                               Compression compression, int64_t data_size, int volume_count);
};

struct DiskRef {
    int index = 0;
    std::string path;
    bool readonly = false;
    std::string bus = "VIRTIO";
};
struct DiskEntry {
    static constexpr int index_backing = -1;
    DiskRef ref;
    std::string name, format = "RAW";
    int64_t size = 0;
    std::string archive_path;
    bool attached = true;
    std::string backing_archive;
    std::optional<std::string> target;
    Json::Value json() const;
    static DiskEntry parse(const Json::Value& object);
};
struct BootFile {
    std::string archive_path, name, path, kind;
    int64_t size = 0;
    std::optional<std::string> target;
    Json::Value json() const;
    static BootFile parse(const Json::Value& object);
};
struct Manifest {
    int manifest_version = manifest_version_base;
    std::string format = extension;
    int64_t created_at = 0;
    std::string app_version;
    int app_version_code = 0;
    std::string app_build_type;
    Compression compression = Compression::zstd;
    Json::Value vm{Json::objectValue};
    std::vector<DiskEntry> disks;
    std::vector<BootFile> boots;
    std::vector<Json::Value> networks;
    Json::Value json() const;
    // The oldest version that can describe the package (resolveVersion).
    int resolve_version() const;
    DiskEntry* find_disk(const std::string& archive);
    BootFile* find_boot(const std::string& archive);
    // fromJson after decodeUtf8; the VM config is migrated as VMConfig(JSONObject).
    static Manifest parse(std::string_view bytes);
};

struct VolumeEntry { int index = 0; int64_t size = 0; int64_t crc32 = 0; };
struct VolumeIndex {
    int64_t data_size = 0;
    std::vector<VolumeEntry> volumes;
    std::string json() const;
    static VolumeIndex parse(std::string_view text);
};
std::string volume_name(const std::string& base, int index); // <base>.NNN
bool is_sub_volume(const std::string& path);
std::string master_of(const std::string& path);

// VolumeSplitOutputStream: the compressed stream sliced across sub-volumes.
class VolumeSplitSink final : public Sink {
public:
    VolumeSplitSink(std::string base, int64_t volume_size) : base_(std::move(base)), volume_size_(volume_size) {}
    void write(const char* data, size_t size) override;
    void finish();
    void abort(); // closes without recording, for cleanup
    int64_t data_size() const { return position_; }
    int current_index() const { return index_; }
    int volume_count() const { return static_cast<int>(entries_.size()); }
    const std::vector<VolumeEntry>& entries() const { return entries_; }
    const std::vector<std::string>& files() const { return files_; }
private:
    std::string base_;
    int64_t volume_size_;
    std::vector<VolumeEntry> entries_;
    std::vector<std::string> files_;
    std::unique_ptr<FileSink> current_;
    uint32_t crc_ = 0;
    int64_t current_bytes_ = 0, position_ = 0;
    int index_ = 0;
    bool finished_ = false;
    void roll();
    void close_current();
};

// VolumeSet: the master's index and verified sub-volumes, read back as the
// single-file byte stream PackageInput consumes.
class VolumeSet {
public:
    static VolumeSet discover(const std::string& master);
    int64_t data_size() const { return index_.data_size; }
    int count() const { return static_cast<int>(sub_volumes_.size()); }
    std::unique_ptr<Source> open_logical() const;
private:
    std::string head_;
    uint64_t data_start_ = 0;
    VolumeIndex index_;
    std::vector<std::string> sub_volumes_;
};

// PackageInput: header and manifest checked, then the decompressed tar.
class PackageInput {
public:
    // data_size >= 0 replaces the header's (split packages carry 0 there).
    static std::unique_ptr<PackageInput> open(Source& raw, int64_t data_size = -1);
    Header header;
    Manifest manifest;
    Source& data() { return *data_; }
    void validate_data_consumed();
private:
    PackageInput(Source& raw) : raw_(raw) {}
    Source& raw_;
    std::unique_ptr<LimitedSource> limited_;
    std::unique_ptr<Source> data_;
};
Manifest read_manifest(Source& raw, const Header& header);
}
