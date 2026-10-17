// SPDX-License-Identifier: GPL-3.0-or-later
#include "io.h"
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <climits>
#include <cmath>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <optional>
#include <sys/stat.h>
#include <unistd.h>

namespace droidvm::pkg {
namespace {
const char* errno_name(int error) {
    switch (error) {
        case EPERM: return "EPERM"; case ENOENT: return "ENOENT"; case EIO: return "EIO"; case EBADF: return "EBADF";
        case EAGAIN: return "EAGAIN"; case ENOMEM: return "ENOMEM"; case EACCES: return "EACCES"; case EBUSY: return "EBUSY";
        case EEXIST: return "EEXIST"; case EXDEV: return "EXDEV"; case ENOTDIR: return "ENOTDIR"; case EISDIR: return "EISDIR";
        case EINVAL: return "EINVAL"; case ENFILE: return "ENFILE"; case EMFILE: return "EMFILE"; case EFBIG: return "EFBIG";
        case ENOSPC: return "ENOSPC"; case EROFS: return "EROFS"; case ENAMETOOLONG: return "ENAMETOOLONG";
        case ELOOP: return "ELOOP"; case EDQUOT: return "EDQUOT"; case ESTALE: return "ESTALE"; case ENXIO: return "ENXIO";
        default: return "EUNKNOWN";
    }
}
std::string read_failed(int error) { return errno_message("read", error); }
}
std::string errno_message(const char* operation, int error) {
    return std::string(operation) + " failed: " + errno_name(error) + " (" + std::strerror(error) + ")";
}
size_t read_some(Source& in, char* data, size_t size) {
    size_t done = 0;
    while (done < size) {
        const auto count = in.read(data + done, size - done);
        if (!count) break;
        done += count;
    }
    return done;
}
void read_fully(Source& in, char* data, size_t size, const char* eof) {
    if (read_some(in, data, size) != size) throw Error(eof);
}
void skip_fully(Source& in, uint64_t count, const char* eof) {
    char buffer[8192];
    while (count) {
        const auto got = in.read(buffer, static_cast<size_t>(std::min<uint64_t>(count, sizeof(buffer))));
        if (!got) throw Error(eof);
        count -= got;
    }
}
void read_zero_padding(Source& in, uint64_t count) {
    std::string buffer(buffer_size, '\0');
    while (count) {
        const auto got = in.read(buffer.data(), static_cast<size_t>(std::min<uint64_t>(count, buffer.size())));
        if (!got) throw Error("unexpected end of vmpkg padding");
        for (size_t i = 0; i < got; ++i) if (buffer[i]) throw Error("vmpkg padding is not zero-filled");
        count -= got;
    }
}
void write_zero(Sink& out, uint64_t count) {
    static const std::string zero(buffer_size, '\0');
    while (count) {
        const auto chunk = static_cast<size_t>(std::min<uint64_t>(count, zero.size()));
        out.write(zero.data(), chunk);
        count -= chunk;
    }
}
void drain(Source& in) {
    std::string buffer(buffer_size, '\0');
    while (in.read(buffer.data(), buffer.size())) {}
}
size_t MemorySource::read(char* data, size_t size) {
    const auto count = std::min(size, data_.size() - offset_);
    std::memcpy(data, data_.data() + offset_, count);
    offset_ += count;
    return count;
}
size_t ZeroSource::read(char* data, size_t size) {
    const auto count = static_cast<size_t>(std::min<uint64_t>(size, remaining_));
    std::memset(data, 0, count);
    remaining_ -= count;
    return count;
}
size_t ChainSource::read(char* data, size_t size) {
    while (index_ < parts_.size()) {
        if (const auto count = parts_[index_]->read(data, size)) return count;
        ++index_;
    }
    return 0;
}
size_t LimitedSource::read(char* data, size_t size) {
    if (!remaining_ || !size) return 0;
    const auto count = in_.read(data, static_cast<size_t>(std::min<uint64_t>(size, remaining_)));
    remaining_ -= count;
    return count;
}
void LimitedSource::drain() {
    skip_fully(in_, remaining_, "unexpected end of tar entry");
    remaining_ = 0;
}

FileSource::FileSource(const std::string& path) : fd_(open(path.c_str(), O_RDONLY | O_CLOEXEC)), buffer_(buffer_size, '\0') {
    if (fd_.get() < 0) throw Error(path + ": " + errno_message("open", errno));
    struct stat info{};
    if (fstat(fd_.get(), &info) == 0 && S_ISDIR(info.st_mode)) throw Error(path + ": " + errno_message("open", EISDIR));
}
size_t FileSource::read(char* data, size_t size) {
    if (begin_ == end_) {
        // Large reads bypass the buffer.
        if (size >= buffer_.size()) {
            for (;;) {
                const auto count = ::read(fd_.get(), data, size);
                if (count < 0 && errno == EINTR) continue;
                if (count < 0) throw Error(read_failed(errno));
                return static_cast<size_t>(count);
            }
        }
        for (;;) {
            const auto count = ::read(fd_.get(), buffer_.data(), buffer_.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw Error(read_failed(errno));
            begin_ = 0; end_ = static_cast<size_t>(count);
            break;
        }
        if (!end_) return 0;
    }
    const auto count = std::min(size, end_ - begin_);
    std::memcpy(data, buffer_.data() + begin_, count);
    begin_ += count;
    return count;
}

FileSink::FileSink(const std::string& path, Mode mode)
    : fd_(open(path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC |
        (mode == Mode::create_new ? O_EXCL | O_NOFOLLOW : O_TRUNC), 0644)) {
    if (fd_.get() < 0) throw Error(path + ": " + errno_message("open", errno));
    pending_.reserve(buffer_size);
}
FileSink::~FileSink() { try { flush(); } catch (...) {} }
void FileSink::write(const char* data, size_t size) {
    if (fd_.get() < 0) throw Error("Stream Closed");
    if (pending_.size() + size > buffer_size) {
        flush();
        if (size >= buffer_size) {
            pending_.assign(data, size);
            flush();
            return;
        }
    }
    pending_.append(data, size);
}
void FileSink::flush() {
    size_t done = 0;
    while (done < pending_.size()) {
        const auto count = ::write(fd_.get(), pending_.data() + done, pending_.size() - done);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { pending_.erase(0, done); position_ += done; throw Error(errno_message("write", errno)); }
        done += static_cast<size_t>(count);
    }
    position_ += done;
    pending_.clear();
}
void FileSink::write_at(uint64_t offset, std::string_view data) {
    flush();
    size_t done = 0;
    while (done < data.size()) {
        const auto count = pwrite(fd_.get(), data.data() + done, data.size() - done, static_cast<off_t>(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw Error(errno_message("write", errno));
        done += static_cast<size_t>(count);
    }
}
void FileSink::close() {
    if (fd_.get() < 0) return;
    flush();
    fd_ = Fd();
}

bool has(const Json::Value& object, const char* key) { return object.isObject() && object.isMember(key); }
namespace {
std::string java_double(double value) {
    if (std::isnan(value)) return "NaN";
    if (std::isinf(value)) return value > 0 ? "Infinity" : "-Infinity";
    char buffer[64];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
    std::string text(buffer, result.ptr);
    if (text.find_first_of(".e") == std::string::npos) text += ".0";
    return text;
}
std::optional<double> parse_double(const std::string& raw) {
    const auto text = java_trim(raw);
    if (text.empty()) return std::nullopt;
    if (text == "NaN" || text == "+NaN" || text == "-NaN") return std::nan("");
    if (text == "Infinity" || text == "+Infinity") return INFINITY;
    if (text == "-Infinity") return -INFINITY;
    std::string digits = text;
    if (!digits.empty() && (digits.back() == 'd' || digits.back() == 'D' || digits.back() == 'f' || digits.back() == 'F')) digits.pop_back();
    char* end = nullptr;
    errno = 0;
    const double value = std::strtod(digits.c_str(), &end);
    if (end == digits.c_str() || *end) return std::nullopt;
    if (digits.find_first_of("xXnNiI") != std::string::npos) return std::nullopt;
    return value;
}
int64_t saturate(double value) {
    if (std::isnan(value)) return 0;
    if (value >= 9223372036854775807.0) return INT64_MAX;
    if (value <= -9223372036854775808.0) return INT64_MIN;
    return static_cast<int64_t>(value);
}
int32_t saturate_int(double value) {
    if (std::isnan(value)) return 0;
    if (value >= 2147483647.0) return INT32_MAX;
    if (value <= -2147483648.0) return INT32_MIN;
    return static_cast<int32_t>(value);
}
bool integral(const Json::Value& value) {
    return (value.type() == Json::intValue || value.type() == Json::uintValue) && value.isInt64();
}
}
std::string opt_string(const Json::Value& object, const char* key, const std::string& fallback) {
    if (!has(object, key)) return fallback;
    const auto& value = object[key];
    if (value.isString()) return value.asString();
    if (value.isNull()) return "null";
    if (value.isBool()) return value.asBool() ? "true" : "false";
    if (integral(value)) return std::to_string(value.asInt64());
    if (value.isUInt64()) return java_double(static_cast<double>(value.asUInt64()));
    if (value.isDouble()) return java_double(value.asDouble());
    return java_json(value);
}
int64_t opt_long(const Json::Value& object, const char* key, int64_t fallback) {
    if (!has(object, key)) return fallback;
    const auto& value = object[key];
    if (integral(value)) return value.asInt64();
    if (value.isUInt64()) return INT64_MAX;
    if (value.isDouble()) return saturate(value.asDouble());
    if (value.isString()) if (auto number = parse_double(value.asString())) return saturate(*number);
    return fallback;
}
int32_t opt_int(const Json::Value& object, const char* key, int32_t fallback) {
    if (!has(object, key)) return fallback;
    const auto& value = object[key];
    // Long.intValue keeps the low 32 bits; Double.intValue saturates.
    if (integral(value)) return static_cast<int32_t>(static_cast<uint32_t>(static_cast<uint64_t>(value.asInt64())));
    if (value.isUInt64()) return INT32_MAX;
    if (value.isDouble()) return saturate_int(value.asDouble());
    if (value.isString()) if (auto number = parse_double(value.asString())) return saturate_int(*number);
    return fallback;
}
bool opt_bool(const Json::Value& object, const char* key, bool fallback) {
    if (!has(object, key)) return fallback;
    const auto& value = object[key];
    if (value.isBool()) return value.asBool();
    if (value.isString()) {
        auto text = value.asString();
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (text == "true") return true;
        if (text == "false") return false;
    }
    return fallback;
}
std::string opt_enum(const Json::Value& object, const char* key, const char* fallback, const std::vector<const char*>& names) {
    auto text = opt_string(object, key, fallback);
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    for (const auto* name : names) if (text == name) return text;
    return fallback;
}
namespace {
void quote(std::string& out, const std::string& text) {
    out += '"';
    for (size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '/': out += "\\/"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) {
                    char escape[8];
                    std::snprintf(escape, sizeof(escape), "\\u%04x", c);
                    out += escape;
                } else if (c == 0xe2 && i + 2 < text.size() && static_cast<unsigned char>(text[i + 1]) == 0x80 &&
                           (static_cast<unsigned char>(text[i + 2]) == 0xa8 || static_cast<unsigned char>(text[i + 2]) == 0xa9)) {
                    out += static_cast<unsigned char>(text[i + 2]) == 0xa8 ? "\\u2028" : "\\u2029";
                    i += 2;
                } else out += static_cast<char>(c);
        }
    }
    out += '"';
}
void newline(std::string& out, int indent, int depth) {
    if (!indent) return;
    out += '\n';
    out.append(static_cast<size_t>(indent * depth), ' ');
}
void emit(std::string& out, const Json::Value& value, int indent, int depth) {
    if (depth > 128) throw Error("JSON nesting too deep");
    switch (value.type()) {
        case Json::nullValue: out += "null"; break;
        case Json::booleanValue: out += value.asBool() ? "true" : "false"; break;
        case Json::intValue: out += std::to_string(value.asInt64()); break;
        case Json::uintValue: out += std::to_string(value.asUInt64()); break;
        case Json::realValue: {
            const double number = value.asDouble();
            const auto whole = saturate(number);
            // JSONObject.numberToString writes integral doubles as longs.
            if (std::isfinite(number) && number == static_cast<double>(whole)) out += std::to_string(whole);
            else out += java_double(number);
            break;
        }
        case Json::stringValue: quote(out, value.asString()); break;
        case Json::arrayValue:
            out += '[';
            for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
                if (i) out += ',';
                newline(out, indent, depth + 1);
                emit(out, value[i], indent, depth + 1);
            }
            if (value.size()) newline(out, indent, depth);
            out += ']';
            break;
        case Json::objectValue: {
            out += '{';
            bool first = true;
            for (const auto& name : value.getMemberNames()) {
                if (!first) out += ',';
                first = false;
                newline(out, indent, depth + 1);
                quote(out, name);
                out += indent ? ": " : ":";
                emit(out, value[name], indent, depth + 1);
            }
            if (!first) newline(out, indent, depth);
            out += '}';
            break;
        }
    }
}
}
std::string java_json(const Json::Value& value, int indent) {
    std::string out;
    emit(out, value, indent, 0);
    return out;
}
Json::Value parse_object(std::string_view text) {
    Json::CharReaderBuilder builder;
    builder["failIfExtra"] = false;
    builder["stackLimit"] = 128;
    builder["allowComments"] = false;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value value;
    std::string error;
    bool parsed = false;
    try { parsed = reader->parse(text.data(), text.data() + text.size(), &value, &error); } catch (const std::exception&) {}
    if (!parsed) throw Error("Value is not valid JSON");
    if (!value.isObject()) throw Error("Value of type " + std::string(value.isArray() ? "org.json.JSONArray" : "java.lang.String") +
                                       " cannot be converted to JSONObject");
    return value;
}
bool valid_utf8(std::string_view text) {
    size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        size_t extra;
        uint32_t code;
        if (c < 0x80) { ++i; continue; }
        if ((c & 0xe0) == 0xc0) { extra = 1; code = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { extra = 2; code = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { extra = 3; code = c & 0x07; }
        else return false;
        for (size_t k = 1; k <= extra; ++k) {
            if (i + k >= text.size()) return false;
            const auto next = static_cast<unsigned char>(text[i + k]);
            if ((next & 0xc0) != 0x80) return false;
            code = code << 6 | (next & 0x3f);
        }
        if ((extra == 1 && code < 0x80) || (extra == 2 && code < 0x800) || (extra == 3 && code < 0x10000)) return false;
        if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
        i += extra + 1;
    }
    return true;
}
size_t java_length(std::string_view text) {
    size_t length = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if ((c & 0xc0) == 0x80) continue;
        length += (c & 0xf8) == 0xf0 ? 2 : 1;
    }
    return length;
}

std::string basename(std::string path) {
    while (!path.empty() && path.back() == '/') path.pop_back();
    const auto slash = path.rfind('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}
std::string dirname(std::string path) {
    while (!path.empty() && path.back() == '/') path.pop_back();
    const auto slash = path.rfind('/');
    return slash == std::string::npos ? std::string() : path.substr(0, slash);
}
std::string path_join(std::string base, std::string child) {
    if (!base.empty() && base.back() == '/') base.pop_back();
    if (!child.empty() && child.front() == '/') child.erase(0, 1);
    return base + "/" + child;
}
std::string java_trim(const std::string& text) {
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= ' ') ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= ' ') --last;
    return text.substr(first, last - first);
}
std::string safe_file_name(const std::string& name, const std::string& fallback) {
    std::string out = name;
    for (auto& c : out) {
        const auto value = static_cast<unsigned char>(c);
        if (value < 0x20 || value == 0x7f || std::strchr("\\/:*?\"<>|", c)) c = '_';
    }
    out = java_trim(out);
    if (out.empty() || out == "." || out == "..") return fallback;
    return out;
}
namespace {
// java.io.File path normalisation: no duplicate or trailing separators.
std::string normalize(const std::string& path) {
    std::string out;
    for (const char c : path) {
        if (c == '/' && !out.empty() && out.back() == '/') continue;
        out += c;
    }
    if (out.size() > 1 && out.back() == '/') out.pop_back();
    return out;
}
std::vector<std::string> components(const std::string& path) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= path.size()) {
        const auto slash = path.find('/', start);
        const auto part = path.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (!part.empty() && part != ".") {
            if (part == "..") { if (!parts.empty()) parts.pop_back(); }
            else parts.push_back(part);
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return parts;
}
}
std::string canonical_path(const std::string& input) {
    if (input.empty()) return input;
    std::string path = normalize(input);
    if (path.front() != '/') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) return input;
        path = std::string(cwd) + "/" + path;
    }
    // realpath of the longest existing prefix, then the rest lexically.
    const auto parts = components(path);
    for (size_t keep = parts.size() + 1; keep-- > 0;) {
        std::string prefix = "/";
        for (size_t i = 0; i < keep; ++i) prefix += (i ? "/" : "") + parts[i];
        char resolved[PATH_MAX];
        if (!realpath(prefix.c_str(), resolved)) continue;
        std::string result = resolved;
        for (size_t i = keep; i < parts.size(); ++i) result += (result == "/" ? "" : "/") + parts[i];
        return result;
    }
    return input;
}
std::string java_path(const std::string& path) { return normalize(path); }
std::string file_name(const std::string& path) {
    const auto normal = normalize(path);
    const auto slash = normal.rfind('/');
    return slash == std::string::npos ? normal : normal.substr(slash + 1);
}
bool is_file(const std::string& path) {
    struct stat info{};
    return stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
}
bool exists(const std::string& path) {
    struct stat info{};
    return stat(path.c_str(), &info) == 0;
}
int64_t file_length(const std::string& path) {
    struct stat info{};
    return stat(path.c_str(), &info) == 0 ? static_cast<int64_t>(info.st_size) : 0;
}
bool make_dirs(const std::string& path) {
    if (exists(path)) return false;
    const auto parent = dirname(normalize(path));
    if (!parent.empty() && !exists(parent)) make_dirs(parent);
    return mkdir(path.c_str(), 0777) == 0;
}
namespace {
void delete_at(int parent, const std::string& name) {
    struct stat observed{};
    if (fstatat(parent, name.c_str(), &observed, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return;
        throw Error(errno_message("stat cleanup entry", errno));
    }
    if (!S_ISDIR(observed.st_mode)) {
        if (unlinkat(parent, name.c_str(), 0) != 0 && errno != ENOENT)
            throw Error(errno_message("unlink cleanup entry", errno));
        return;
    }
    Fd child(openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (child.get() < 0) throw Error(errno_message("open cleanup directory", errno));
    struct stat opened{};
    if (fstat(child.get(), &opened) != 0) throw Error(errno_message("stat cleanup directory", errno));
    if (opened.st_dev != observed.st_dev || opened.st_ino != observed.st_ino)
        throw Error("Cleanup directory changed before traversal");
    // Enumerate and recurse relative to the opened directory, never by reconstructing
    // paths that can follow a replaced ancestor symlink.
    const int duplicate = fcntl(child.get(), F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) throw Error(errno_message("duplicate cleanup directory", errno));
    DIR* raw = fdopendir(duplicate);
    if (!raw) { const int error = errno; ::close(duplicate); throw Error(errno_message("read cleanup directory", error)); }
    std::unique_ptr<DIR, int(*)(DIR*)> directory(raw, closedir);
    for (;;) {
        errno = 0;
        auto* entry = readdir(directory.get());
        if (!entry) {
            if (errno) throw Error(errno_message("read cleanup directory", errno));
            break;
        }
        const std::string entry_name = entry->d_name;
        if (entry_name != "." && entry_name != "..") delete_at(child.get(), entry_name);
    }
    struct stat current{};
    if (fstatat(parent, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0)
        throw Error(errno_message("verify cleanup directory", errno));
    if (current.st_dev != opened.st_dev || current.st_ino != opened.st_ino)
        throw Error("Cleanup directory changed during traversal");
    if (unlinkat(parent, name.c_str(), AT_REMOVEDIR) != 0)
        throw Error(errno_message("remove cleanup directory", errno));
}
}
void delete_tree(const std::string& path) {
    const auto normalized = java_path(path);
    const auto name = file_name(normalized);
    if (name.empty() || name == "." || name == ".." || normalized == "/")
        throw Error("Invalid cleanup root");
    auto parent_path = dirname(normalized);
    if (parent_path.empty()) parent_path = ".";
    Fd parent(open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (parent.get() < 0) {
        if (errno == ENOENT) return;
        throw Error(errno_message("open cleanup parent", errno));
    }
    delete_at(parent.get(), name);
}
}
