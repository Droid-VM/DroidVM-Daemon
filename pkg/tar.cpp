// SPDX-License-Identifier: GPL-3.0-or-later
#include "tar.h"
#include <cstring>
#include <ctime>

namespace droidvm::pkg {
namespace {
constexpr size_t block_size = 512;
std::string octal(uint64_t value, size_t digits) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%llo", static_cast<unsigned long long>(value));
    std::string text = buffer;
    if (text.size() < digits) text.insert(0, digits - text.size(), '0');
    return text;
}
void field(char* header, size_t offset, size_t length, const std::string& text) {
    const auto count = std::min(text.size(), length);
    std::memcpy(header + offset, text.data(), count);
    std::memset(header + offset + count, 0, length - count);
}
// Writes exactly the declared size, as OutputStreamLimiter.
class Limiter final : public Sink {
public:
    Limiter(Sink& out, uint64_t size) : out_(out), remaining_(size) {}
    void write(const char* data, size_t size) override {
        if (size > remaining_) throw Error("entry overwrote its declared size");
        out_.write(data, size);
        remaining_ -= size;
    }
    uint64_t remaining() const { return remaining_; }
private:
    Sink& out_;
    uint64_t remaining_;
};
std::string cstr(const char* header, size_t offset, size_t length) {
    size_t end = offset;
    while (end < offset + length && header[end]) ++end;
    return std::string(header + offset, end - offset);
}
int64_t parse_octal(const char* header, size_t offset, size_t length) {
    const auto first = static_cast<unsigned char>(header[offset]);
    if (first & 0x80) {
        uint64_t value = first & 0x7f;
        for (size_t i = offset + 1; i < offset + length; ++i) value = value << 8 | static_cast<unsigned char>(header[i]);
        return static_cast<int64_t>(value);
    }
    const auto text = java_trim(cstr(header, offset, length));
    if (text.empty()) return 0;
    // Long.parseLong(text, 8): optional sign, octal digits, no overflow.
    size_t i = 0;
    bool negative = false;
    if (text[0] == '+' || text[0] == '-') { negative = text[0] == '-'; i = 1; }
    if (i == text.size()) return 0;
    uint64_t value = 0;
    for (; i < text.size(); ++i) {
        if (text[i] < '0' || text[i] > '7') return 0;
        if (value > (uint64_t(1) << 60)) return 0;
        value = value * 8 + static_cast<uint64_t>(text[i] - '0');
    }
    if (!negative && value > static_cast<uint64_t>(INT64_MAX)) return 0;
    if (negative && value > uint64_t(1) << 63) return 0;
    return negative ? static_cast<int64_t>(0 - value) : static_cast<int64_t>(value);
}
bool null_block(const char* header) {
    for (size_t i = 0; i < block_size; ++i) if (header[i]) return false;
    return true;
}
uint64_t pad(int64_t size) { return (block_size - static_cast<uint64_t>(size) % block_size) % block_size; }
}
void TarWriter::header(const std::string& name, int64_t size, char type) {
    char block[block_size] = {};
    std::memcpy(block, name.data(), std::min<size_t>(name.size(), 100));
    field(block, 100, 8, octal(0644, 7));
    field(block, 108, 8, octal(0, 7));
    field(block, 116, 8, octal(0, 7));
    if (static_cast<uint64_t>(size) > 0777777777777ull) {
        block[124] = static_cast<char>(0x80);
        auto value = static_cast<uint64_t>(size);
        for (int i = 135; i >= 125; --i) { block[i] = static_cast<char>(value & 0xff); value >>= 8; }
    } else field(block, 124, 12, octal(static_cast<uint64_t>(size), 11));
    field(block, 136, 12, octal(static_cast<uint64_t>(std::time(nullptr)), 11));
    std::memset(block + 148, ' ', 8);
    block[156] = type;
    std::memcpy(block + 257, "ustar", 5);
    unsigned sum = 0;
    for (const char c : block) sum += static_cast<unsigned char>(c);
    field(block, 148, 8, octal(sum, 0) + " ");
    out_.write(block, block_size);
}
void TarWriter::entry(const std::string& input, int64_t size, const Content& content) {
    if (closed_) throw Error("TarWriter closed");
    auto name = input;
    if (java_length(name) > 100) {
        entry("./@LongLink", name);
        const auto slash = name.rfind('/');
        if (slash != std::string::npos && slash < name.size() - 1) name = name.substr(slash + 1);
    }
    header(name, size, '0');
    Limiter sink(out_, static_cast<uint64_t>(size));
    content(sink);
    if (sink.remaining()) throw Error("entry " + name + ": short write (" + std::to_string(static_cast<uint64_t>(size) - sink.remaining()) +
                                      " of " + std::to_string(size) + " bytes)");
    write_zero(out_, pad(size));
}
void TarWriter::entry(const std::string& name, std::string_view bytes) {
    entry(name, static_cast<int64_t>(bytes.size()), [&](Sink& out) { out.append(bytes); });
}
void TarWriter::close() {
    if (closed_) return;
    closed_ = true;
    write_zero(out_, block_size * 2);
}
bool TarReader::block(char* header) {
    const auto count = read_some(in_, header, block_size);
    if (count == block_size) return true;
    if (count == 0) { eof_ = true; std::memset(header, 0, block_size); return true; }
    throw Error("unexpected end of tar header");
}
void TarReader::for_each(const Handler& handler) {
    char header[block_size];
    while (!eof_) {
        block(header);
        if (null_block(header)) { eof_ = true; return; }
        auto name = cstr(header, 0, 100);
        int type = static_cast<unsigned char>(header[156]);
        auto size = parse_octal(header, 124, 12);
        auto mode = static_cast<int>(parse_octal(header, 100, 8));
        if (type == 'L') {
            if (size < 0 || size > (16 << 20)) throw Error("tar long name is too large");
            std::string long_name(static_cast<size_t>(size), '\0');
            read_fully(in_, long_name.data(), long_name.size(), "unexpected end of tar entry");
            skip_fully(in_, pad(size), "unexpected end of tar entry");
            name = java_trim(long_name);
            block(header);
            if (null_block(header)) { eof_ = true; return; }
            size = parse_octal(header, 124, 12);
            mode = static_cast<int>(parse_octal(header, 100, 8));
            type = static_cast<unsigned char>(header[156]);
        }
        if (size < 0) size = 0;
        if (type != '0' && type != 0) {
            skip_fully(in_, static_cast<uint64_t>(size), "unexpected end of tar entry");
            skip_fully(in_, pad(size), "unexpected end of tar entry");
            continue;
        }
        LimitedSource content(in_, static_cast<uint64_t>(size));
        handler(name, mode, size, content);
        content.drain();
        skip_fully(in_, pad(size), "unexpected end of tar entry");
    }
}
}
