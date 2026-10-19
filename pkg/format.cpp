// SPDX-License-Identifier: GPL-3.0-or-later
#include "format.h"
#include "store/vm_config.h"
#include <zlib.h>
#include <algorithm>
#include <cstring>
#include <sys/stat.h>

namespace droidvm::pkg {
namespace {
int u16(const char* bytes, size_t offset) {
    return static_cast<unsigned char>(bytes[offset]) | static_cast<unsigned char>(bytes[offset + 1]) << 8;
}
void put_u16(char* bytes, size_t offset, int64_t value) {
    if (value < 0 || value > 0xffff) throw Error("uint16 out of range: " + std::to_string(value));
    bytes[offset] = static_cast<char>(value & 0xff);
    bytes[offset + 1] = static_cast<char>((value >> 8) & 0xff);
}
std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}
// JSONObject.getJSONArray / getJSONObject texts.
const Json::Value& required(const Json::Value& object, const char* key, bool array) {
    if (!object.isMember(key) || object[key].isNull()) throw Error(std::string("No value for ") + key);
    const auto& value = object[key];
    if (array ? !value.isArray() : !value.isObject())
        throw Error(std::string("Value at ") + key + " cannot be converted to " + (array ? "JSONArray" : "JSONObject"));
    return value;
}
}
std::string disk_format_of(const std::string& filename) {
    // DiskFormat.fromExt(extensionLower(name)); RAW's extension is "img".
    const auto dot = filename.rfind('.');
    const auto ext = lower(dot == std::string::npos ? std::string() : filename.substr(dot + 1));
    if (ext == "qcow2") return "QCOW2";
    if (ext == "vhdx") return "VHDX";
    if (ext == "vdi") return "VDI";
    if (ext == "vmdk") return "VMDK";
    if (ext == "iso") return "ISO";
    return "RAW";
}
Header Header::parse(const char* bytes) {
    if (std::memcmp(bytes, "VMPKG", 5) != 0 || bytes[5] != 0) throw Error("invalid package header");
    Header header;
    header.manifest_version = u16(bytes, 6);
    header.app_version_code = u16(bytes, 8);
    header.manifest_size = u16(bytes, 10);
    header.compression = u16(bytes, 12);
    header.volume_count = u16(bytes, 14);
    uint64_t size = 0;
    for (int i = 7; i >= 0; --i) size = size << 8 | static_cast<unsigned char>(bytes[16 + i]);
    header.data_size = static_cast<int64_t>(size);
    if (header.manifest_version < manifest_version_base || header.manifest_version > pkg::manifest_version)
        throw Error("unsupported vmpkg manifest version: " + std::to_string(header.manifest_version));
    if (!compression_from_type(header.compression)) throw Error("unsupported vmpkg compression: " + std::to_string(header.compression));
    if (header.manifest_size <= 0) throw Error("empty vmpkg manifest");
    if (header.data_size < 0) throw Error("vmpkg data size is too large");
    return header;
}
std::array<char, header_size> Header::build(int version, int app_version_code, size_t manifest_size, Compression compression,
                                            int64_t data_size, int volume_count) {
    std::array<char, header_size> bytes{};
    std::memcpy(bytes.data(), "VMPKG", 5);
    put_u16(bytes.data(), 6, version);
    put_u16(bytes.data(), 8, app_version_code);
    put_u16(bytes.data(), 10, static_cast<int64_t>(manifest_size));
    put_u16(bytes.data(), 12, static_cast<int>(compression));
    put_u16(bytes.data(), 14, volume_count);
    if (data_size < 0) throw Error("uint64 out of range: " + std::to_string(data_size));
    for (int i = 0; i < 8; ++i) bytes[16 + i] = static_cast<char>((static_cast<uint64_t>(data_size) >> (i * 8)) & 0xff);
    return bytes;
}

Json::Value DiskEntry::json() const {
    Json::Value object;
    object["index"] = ref.index;
    object["readonly"] = ref.readonly;
    object["bus"] = ref.bus;
    object["path"] = ref.path;
    if (target) {
        object["path"] = *target;
        object["name"] = file_name(*target);
    } else object["name"] = name;
    object["format"] = lower(format);
    object["size"] = Json::Int64(size);
    object["archive_path"] = archive_path;
    object["attached"] = attached;
    if (!backing_archive.empty()) object["backing_archive"] = backing_archive;
    return object;
}
DiskEntry DiskEntry::parse(const Json::Value& object) {
    if (!object.isObject()) throw Error("object is not json");
    DiskEntry entry;
    entry.ref.index = opt_int(object, "index", 0);
    entry.ref.path = opt_string(object, "path", "");
    entry.ref.readonly = opt_bool(object, "readonly", false);
    entry.ref.bus = opt_enum(object, "bus", "VIRTIO", disk_buses);
    entry.name = opt_string(object, "name", "disk.img");
    entry.format = opt_enum(object, "format", "RAW", disk_formats);
    entry.size = opt_long(object, "size");
    entry.archive_path = opt_string(object, "archive_path");
    entry.attached = opt_bool(object, "attached", true);
    entry.backing_archive = opt_string(object, "backing_archive", "");
    return entry;
}
Json::Value BootFile::json() const {
    Json::Value object;
    object["archive_path"] = archive_path;
    object["name"] = name;
    object["path"] = path;
    object["kind"] = kind;
    object["size"] = Json::Int64(size);
    return object;
}
BootFile BootFile::parse(const Json::Value& object) {
    if (!object.isObject()) throw Error("object is not json");
    BootFile file;
    file.archive_path = opt_string(object, "archive_path");
    file.name = opt_string(object, "name");
    file.path = opt_string(object, "path");
    file.kind = opt_string(object, "kind");
    file.size = opt_long(object, "size");
    return file;
}
Json::Value Manifest::json() const {
    Json::Value object;
    object["manifest_version"] = manifest_version;
    object["format"] = format;
    object["created_at"] = Json::Int64(created_at);
    object["app_version"] = app_version;
    object["app_version_code"] = app_version_code;
    object["app_build_type"] = app_build_type;
    object["compression"] = compression_name(compression);
    object["vm"] = vm;
    auto& disk_rows = object["disks"] = Json::Value(Json::arrayValue);
    for (const auto& disk : disks) disk_rows.append(disk.json());
    auto& boot_rows = object["boots"] = Json::Value(Json::arrayValue);
    for (const auto& boot : boots) boot_rows.append(boot.json());
    auto& network_rows = object["networks"] = Json::Value(Json::arrayValue);
    for (const auto& network : networks) network_rows.append(network);
    return object;
}
int Manifest::resolve_version() const {
    for (const auto& disk : disks)
        if (!disk.attached || !disk.backing_archive.empty()) return manifest_version_backing_chain;
    return manifest_version_base;
}
DiskEntry* Manifest::find_disk(const std::string& archive) {
    for (auto& disk : disks) if (disk.archive_path == archive) return &disk;
    return nullptr;
}
BootFile* Manifest::find_boot(const std::string& archive) {
    for (auto& boot : boots) if (boot.archive_path == archive) return &boot;
    return nullptr;
}
Manifest Manifest::parse(std::string_view bytes) {
    if (!valid_utf8(bytes)) throw Error("vmpkg manifest is not valid UTF-8");
    const auto object = parse_object(bytes);
    Manifest manifest;
    manifest.manifest_version = opt_int(object, "manifest_version");
    manifest.format = opt_string(object, "format");
    manifest.created_at = opt_long(object, "created_at");
    manifest.app_version = opt_string(object, "app_version");
    manifest.app_version_code = opt_int(object, "app_version_code");
    manifest.app_build_type = opt_string(object, "app_build_type");
    manifest.compression = compression_from_name(opt_enum(object, "compression", "ZSTD", compression_names));
    const auto& vm = required(object, "vm", false);
    try { manifest.vm = config::migrate_vm(vm); }
    catch (const std::exception& error) { throw Error(error.what()); }
    for (const auto& row : required(object, "disks", true)) manifest.disks.push_back(DiskEntry::parse(row));
    for (const auto& row : required(object, "boots", true)) manifest.boots.push_back(BootFile::parse(row));
    for (const auto& row : required(object, "networks", true)) {
        if (!row.isObject()) throw Error("object is not json");
        // NetworkConfig(JSONObject) only accepts the current schema.
        if (opt_int(row, "schema", 0) != 2) throw Error("Unsupported network config schema (expected 2)");
        manifest.networks.push_back(row);
    }
    return manifest;
}

std::string VolumeIndex::json() const {
    // JSONObject insertion order: magic, version, data_size, volumes.
    std::string out = "{\"magic\":\"" + std::string(volume_magic) + "\",\"version\":" + std::to_string(volume_version) +
                      ",\"data_size\":" + std::to_string(data_size) + ",\"volumes\":[";
    for (size_t i = 0; i < volumes.size(); ++i) {
        if (i) out += ',';
        out += "{\"index\":" + std::to_string(volumes[i].index) + ",\"size\":" + std::to_string(volumes[i].size) +
               ",\"crc32\":" + std::to_string(volumes[i].crc32) + "}";
    }
    return out + "]}";
}
VolumeIndex VolumeIndex::parse(std::string_view text) {
    Json::Value object;
    try { object = parse_object(text); } catch (const Error&) { throw Error("failed to parse volume index"); }
    if (opt_string(object, "magic") != volume_magic) throw Error("missing volume index magic");
    const auto version = opt_int(object, "version");
    if (version != volume_version) throw Error("unsupported volume version: " + std::to_string(version));
    VolumeIndex index;
    index.data_size = opt_long(object, "data_size");
    if (!object.isMember("volumes") || !object["volumes"].isArray()) throw Error("failed to parse volume index");
    for (const auto& row : object["volumes"]) {
        if (!row.isObject()) throw Error("failed to parse volume index");
        index.volumes.push_back({opt_int(row, "index"), opt_long(row, "size"), opt_long(row, "crc32")});
    }
    if (index.volumes.empty()) throw Error("volume index has no volumes");
    return index;
}
std::string volume_name(const std::string& base, int index) {
    char suffix[16];
    std::snprintf(suffix, sizeof(suffix), ".%03d", index);
    return base + suffix;
}
bool is_sub_volume(const std::string& path) {
    // ".*\\.\\d{3}": "." matches no line terminator in String.matches.
    if (path.size() < 4 || path.find_first_of("\n\r") != std::string::npos) return false;
    const auto tail = path.substr(path.size() - 4);
    return tail[0] == '.' && std::all_of(tail.begin() + 1, tail.end(), [](char c) { return c >= '0' && c <= '9'; });
}
std::string master_of(const std::string& path) { return is_sub_volume(path) ? path.substr(0, path.size() - 4) : path; }

void VolumeSplitSink::write(const char* data, size_t size) {
    if (finished_) throw Error("volume stream already finished");
    while (size) {
        if (!current_ || current_bytes_ >= volume_size_) roll();
        const auto chunk = static_cast<size_t>(std::min<int64_t>(static_cast<int64_t>(size), volume_size_ - current_bytes_));
        current_->write(data, chunk);
        crc_ = static_cast<uint32_t>(crc32(crc_, reinterpret_cast<const Bytef*>(data), static_cast<uInt>(chunk)));
        current_bytes_ += static_cast<int64_t>(chunk);
        position_ += static_cast<int64_t>(chunk);
        data += chunk;
        size -= chunk;
    }
}
void VolumeSplitSink::roll() {
    if (current_) close_current();
    ++index_;
    if (index_ > volume_max_count)
        throw Error("too many volumes (> " + std::to_string(volume_max_count) + "); use a larger volume size");
    const auto path = volume_name(base_, index_);
    files_.push_back(path);
    current_ = std::make_unique<FileSink>(path);
    crc_ = static_cast<uint32_t>(crc32(0, nullptr, 0));
    current_bytes_ = 0;
}
void VolumeSplitSink::close_current() {
    entries_.push_back({index_, current_bytes_, static_cast<int64_t>(crc_)});
    auto closing = std::move(current_);
    if (completed_) { closing->flush(); completed_(volume_name(base_, index_), closing->fd()); }
    closing->close();
}
void VolumeSplitSink::finish() {
    if (finished_) return;
    if (current_) close_current();
    finished_ = true;
}
void VolumeSplitSink::abort() {
    if (!current_) return;
    try { current_->close(); } catch (...) {}
    current_.reset();
}

namespace {
class SubVolumes final : public Source {
public:
    SubVolumes(const std::vector<std::string>& files, const std::vector<VolumeEntry>& entries, VolumeSet::Open open)
        : files_(files), entries_(entries), open_(std::move(open)) {}
    size_t read(char* data, size_t size) override {
        for (;;) {
            if (!current_ || !remaining_) {
                if (!advance()) return 0;
                continue;
            }
            const auto want = static_cast<size_t>(std::min<uint64_t>(size, remaining_));
            const auto count = current_->read(data, want);
            if (!count) throw Error("sub-volume " + std::to_string(index_ + 1) + " ended early");
            crc_ = static_cast<uint32_t>(crc32(crc_, reinterpret_cast<const Bytef*>(data), static_cast<uInt>(count)));
            remaining_ -= count;
            return count;
        }
    }
private:
    const std::vector<std::string>& files_;
    const std::vector<VolumeEntry>& entries_;
    VolumeSet::Open open_;
    std::unique_ptr<FileSource> current_;
    int index_ = -1;
    uint32_t crc_ = 0;
    uint64_t remaining_ = 0;
    bool advance() {
        if (current_) {
            if (remaining_) throw Error("sub-volume " + std::to_string(index_ + 1) + " truncated");
            if (static_cast<int64_t>(crc_) != entries_[static_cast<size_t>(index_)].crc32)
                throw Error("sub-volume " + std::to_string(index_ + 1) + " checksum mismatch");
            current_.reset();
        }
        if (++index_ >= static_cast<int>(files_.size())) { index_ = static_cast<int>(files_.size()); return false; }
        const auto& path = files_[static_cast<size_t>(index_)];
        current_ = open_ ? std::make_unique<FileSource>(open_(path)) : std::make_unique<FileSource>(path);
        crc_ = static_cast<uint32_t>(crc32(0, nullptr, 0));
        const auto size = entries_[static_cast<size_t>(index_)].size;
        remaining_ = size > 0 ? static_cast<uint64_t>(size) : 0;
        return true;
    }
};
}
VolumeSet VolumeSet::discover(const std::string& master, Open open) {
    auto length_of = [&](const std::string& path) {
        if (!open) return file_length(path);
        auto file = open(path);
        struct stat info{};
        if (fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode)) throw Error("Invalid package source file");
        return static_cast<int64_t>(info.st_size);
    };
    const auto length = length_of(master);
    if (length <= 0 || length > (16ll << 20)) throw Error("unexpected master size: " + std::to_string(length));
    std::string all(static_cast<size_t>(length), '\0');
    {
        FileSource in(open ? FileSource(open(master)) : FileSource(master));
        if (read_some(in, all.data(), all.size()) != all.size()) throw Error("short read on master");
    }
    if (all.size() < header_size) throw Error("master too small");
    const auto header = Header::parse(all.data());
    if (header.volume_count <= 0) throw Error("not a multi-volume package");
    const auto data_start = align_up_strict(align_up(header_size) + static_cast<uint64_t>(header.manifest_size));
    if (all.size() < data_start) throw Error("truncated master");
    VolumeSet set;
    set.index_ = VolumeIndex::parse(std::string_view(all).substr(data_start));
    if (static_cast<int>(set.index_.volumes.size()) != header.volume_count)
        throw Error("volume count mismatch: header " + std::to_string(header.volume_count) + ", index " + std::to_string(set.index_.volumes.size()));
    for (size_t i = 0; i < set.index_.volumes.size(); ++i) {
        const auto path = volume_name(master, static_cast<int>(i + 1));
        if (!open && !is_file(path)) throw Error("missing sub-volume " + std::to_string(i + 1) + " (" + file_name(path) + ")");
        const auto on_disk = length_of(path);
        if (on_disk != set.index_.volumes[i].size)
            throw Error("sub-volume " + std::to_string(i + 1) + " size mismatch: on-disk " + std::to_string(on_disk) +
                        ", expected " + std::to_string(set.index_.volumes[i].size));
        set.sub_volumes_.push_back(path);
    }
    set.head_ = all.substr(0, data_start);
    set.data_start_ = data_start;
    set.open_ = std::move(open);
    return set;
}
std::unique_ptr<Source> VolumeSet::open_logical() const {
    const auto end = data_start_ + static_cast<uint64_t>(std::max<int64_t>(index_.data_size, 0));
    std::vector<std::unique_ptr<Source>> parts;
    parts.push_back(std::make_unique<MemorySource>(head_));
    parts.push_back(std::make_unique<SubVolumes>(sub_volumes_, index_.volumes, open_));
    parts.push_back(std::make_unique<ZeroSource>(align_up(end) - end));
    return std::make_unique<ChainSource>(std::move(parts));
}

Manifest read_manifest(Source& raw, const Header& header) {
    read_zero_padding(raw, align_up(header_size) - header_size);
    std::string bytes(static_cast<size_t>(header.manifest_size), '\0');
    read_fully(raw, bytes.data(), bytes.size());
    auto manifest = Manifest::parse(bytes);
    if (header.manifest_version != manifest.manifest_version) throw Error("vmpkg manifest_version mismatch");
    if (header.app_version_code != manifest.app_version_code) throw Error("vmpkg app_version_code mismatch");
    if (header.compression != static_cast<int>(manifest.compression)) throw Error("vmpkg compression mismatch");
    return manifest;
}
std::unique_ptr<PackageInput> PackageInput::open(Source& raw, int64_t data_size) {
    char bytes[header_size];
    read_fully(raw, bytes, sizeof(bytes));
    std::unique_ptr<PackageInput> input(new PackageInput(raw));
    input->header = Header::parse(bytes);
    input->manifest = read_manifest(raw, input->header);
    if (data_size >= 0) input->header.data_size = data_size;
    const auto position = align_up(header_size) + static_cast<uint64_t>(input->header.manifest_size);
    read_zero_padding(raw, align_up_strict(position) - position);
    input->limited_ = std::make_unique<LimitedSource>(raw, static_cast<uint64_t>(input->header.data_size));
    input->data_ = decompress(*input->limited_, *compression_from_type(input->header.compression));
    return input;
}
void PackageInput::validate_data_consumed() {
    if (limited_->remaining()) throw Error("vmpkg data_size is larger than tarball data");
    auto end = align_up_strict(align_up(header_size) + static_cast<uint64_t>(header.manifest_size));
    end += static_cast<uint64_t>(header.data_size);
    read_zero_padding(raw_, align_up(end) - end);
    char extra;
    if (raw_.read(&extra, 1)) throw Error("unexpected bytes after vmpkg package");
}
}
