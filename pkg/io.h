// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include <json/json.h>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Byte streams, files and the org.json/StringUtils behaviour the package
// format code relies on. Failures throw Error, the IOException equivalent
// whose message reaches the client.
namespace droidvm::pkg {
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
inline constexpr size_t buffer_size = 64 * 1024; // PackageConstants.BUFFER
// libcore ErrnoException text: "<operation> failed: ENOENT (No such file or directory)".
std::string errno_message(const char* operation, int error);

class Source {
public:
    virtual ~Source() = default;
    // Up to size bytes; 0 only at the end of the stream.
    virtual size_t read(char* data, size_t size) = 0;
};
class Sink {
public:
    virtual ~Sink() = default;
    virtual void write(const char* data, size_t size) = 0;
    void append(std::string_view data) { write(data.data(), data.size()); }
};
size_t read_some(Source& in, char* data, size_t size);
// BinaryUtils.readFully: "unexpected end of vmpkg" unless told otherwise.
void read_fully(Source& in, char* data, size_t size, const char* eof = "unexpected end of vmpkg");
void skip_fully(Source& in, uint64_t count, const char* eof);
void read_zero_padding(Source& in, uint64_t count);
void write_zero(Sink& out, uint64_t count);
// Reads to the end of the stream.
void drain(Source& in);

// BinaryUtils.alignUp / alignUpStrict with the 4 KiB default.
inline uint64_t align_up(uint64_t value, uint64_t align = 0x1000) { return (value + align - 1) & ~(align - 1); }
inline uint64_t align_up_strict(uint64_t value, uint64_t align = 0x1000) {
    const auto aligned = align_up(value, align);
    return aligned == value ? value + align : aligned;
}

class MemorySource final : public Source {
public:
    explicit MemorySource(std::string data) : data_(std::move(data)) {}
    size_t read(char* data, size_t size) override;
private:
    std::string data_;
    size_t offset_ = 0;
};
class ZeroSource final : public Source {
public:
    explicit ZeroSource(uint64_t count) : remaining_(count) {}
    size_t read(char* data, size_t size) override;
private:
    uint64_t remaining_;
};
// SequenceInputStream over owned parts.
class ChainSource final : public Source {
public:
    explicit ChainSource(std::vector<std::unique_ptr<Source>> parts) : parts_(std::move(parts)) {}
    size_t read(char* data, size_t size) override;
private:
    std::vector<std::unique_ptr<Source>> parts_;
    size_t index_ = 0;
};
// LimitedInputStream: at most size bytes of the underlying stream.
class LimitedSource final : public Source {
public:
    LimitedSource(Source& in, uint64_t size) : in_(in), remaining_(size) {}
    size_t read(char* data, size_t size) override;
    uint64_t remaining() const { return remaining_; }
    // "unexpected end of tar entry" when the stream ends first.
    void drain();
private:
    Source& in_;
    uint64_t remaining_;
};
class StringSink final : public Sink {
public:
    void write(const char* data, size_t size) override { value.append(data, size); }
    std::string value;
};

class FileSource final : public Source {
public:
    explicit FileSource(const std::string& path); // FileInputStream
    size_t read(char* data, size_t size) override;
private:
    Fd fd_;
    std::string buffer_;
    size_t begin_ = 0, end_ = 0;
};
// FileOutputStream (truncate) or RandomAccessFile "rw" with setLength(0).
class FileSink final : public Sink {
public:
    enum class Mode { truncate, create_new };
    explicit FileSink(const std::string& path, Mode mode = Mode::truncate);
    // Exclusive file creation relative to an already opened extraction directory.
    FileSink(int directory, const std::string& name);
    ~FileSink() override;
    void write(const char* data, size_t size) override;
    uint64_t position() const { return position_ + pending_.size(); }
    void flush();
    // RandomAccessFile.seek(offset) + write; flushes buffered data first.
    void write_at(uint64_t offset, std::string_view data);
    void close();
    int fd() const { return fd_.get(); } // Borrowed; flush before syncing through a retained handle.
private:
    Fd fd_;
    std::string pending_;
    uint64_t position_ = 0;
};

// org.json JSONObject.opt* coercions on parsed request/manifest objects.
bool has(const Json::Value& object, const char* key);
std::string opt_string(const Json::Value& object, const char* key, const std::string& fallback = {});
int64_t opt_long(const Json::Value& object, const char* key, int64_t fallback = 0);
int32_t opt_int(const Json::Value& object, const char* key, int32_t fallback = 0);
bool opt_bool(const Json::Value& object, const char* key, bool fallback = false);
// Enums.optEnum(JSONObject): optString(key, fallback).toUpperCase() must name a constant.
std::string opt_enum(const Json::Value& object, const char* key, const char* fallback, const std::vector<const char*>& names);
// JSONObject.toString(indent); indent 0 is the compact toString().
std::string java_json(const Json::Value& value, int indent = 0);
// new JSONObject(text); throws Error. Content after the object is ignored, as JSONTokener.
Json::Value parse_object(std::string_view text);
bool valid_utf8(std::string_view text);
// UTF-16 length of UTF-8 text (String.length()).
size_t java_length(std::string_view text);

// StringUtils / FileUtils.
std::string basename(std::string path);
std::string dirname(std::string path);
std::string path_join(std::string base, std::string child);
std::string safe_file_name(const std::string& name, const std::string& fallback);
std::string java_trim(const std::string& text);
// File.getCanonicalPath, falling back to the path itself.
std::string canonical_path(const std::string& path);
// java.io.File's normalised spelling: no duplicate or trailing separators.
std::string java_path(const std::string& path);
// File.getName after File's path normalisation.
std::string file_name(const std::string& path);
bool is_file(const std::string& path);
bool exists(const std::string& path);
int64_t file_length(const std::string& path); // File.length(): 0 when unknown
bool make_dirs(const std::string& path, bool durable = false); // File.mkdirs(); optional directory fsync.
void delete_tree(const std::string& path);
// Retains the parent and new directory identities for an import's whole lifetime.
// Destruction closes handles only; removal is explicit and rejects replacement.
class CreatedDirectory {
public:
    CreatedDirectory(const std::string& parent, const std::string& basename);
    const std::string& path() const { return path_; }
    int fd() const { return directory_.get(); }
    void verify() const;
    void sync() const;
    void remove();
private:
    std::string parent_path_, name_, path_;
    Fd parent_, directory_;
    bool removed_ = false;
};
// Pins the extracted inode and its parent across stream close/header rewriting.
// Identity checks detect replacement; they do not lock out external writers.
class RetainedFile {
public:
    RetainedFile(int file, int directory, const std::string& directory_path, const std::string& name);
    void verify() const;
    void sync() const;
    int fd() const { return file_.get(); }
    std::string path() const { return path_join(directory_path_, name_); }
private:
    Fd file_, directory_;
    std::string directory_path_, name_;
};
}
