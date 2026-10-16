// SPDX-License-Identifier: GPL-3.0-or-later
#include "compression.h"
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>
#include <cstring>

namespace droidvm::pkg {
std::optional<Compression> compression_from_type(int type) {
    if (type < 0 || type > 3) return std::nullopt;
    return static_cast<Compression>(type);
}
const char* compression_name(Compression compression) { return compression_names[static_cast<size_t>(compression)]; }
Compression compression_from_name(const std::string& name) {
    for (size_t i = 0; i < compression_names.size(); ++i) if (name == compression_names[i]) return static_cast<Compression>(i);
    return Compression::zstd;
}
namespace {
class PlainEncoder final : public Encoder {
public:
    explicit PlainEncoder(Sink& out) : out_(out) {}
    void write(const char* data, size_t size) override { out_.write(data, size); }
    void finish() override {}
private:
    Sink& out_;
};

class GzipEncoder final : public Encoder {
public:
    explicit GzipEncoder(Sink& out) : out_(out), buffer_(buffer_size, '\0') {
        // GZIPOutputStream: Deflater.DEFAULT_COMPRESSION, gzip wrapper.
        if (deflateInit2(&stream_, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
            throw Error("failed to initialise gzip");
    }
    ~GzipEncoder() override { deflateEnd(&stream_); }
    void write(const char* data, size_t size) override { run(data, size, Z_NO_FLUSH); }
    void finish() override { if (!finished_) { run(nullptr, 0, Z_FINISH); finished_ = true; } }
private:
    Sink& out_;
    z_stream stream_{};
    std::string buffer_;
    bool finished_ = false;
    void run(const char* data, size_t size, int flush) {
        while (size || flush == Z_FINISH) {
            const auto chunk = static_cast<uInt>(std::min<size_t>(size, 1u << 30));
            stream_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data));
            stream_.avail_in = chunk;
            int result;
            do {
                stream_.next_out = reinterpret_cast<Bytef*>(buffer_.data());
                stream_.avail_out = static_cast<uInt>(buffer_.size());
                result = deflate(&stream_, flush);
                if (result == Z_STREAM_ERROR) throw Error("gzip compression failed");
                out_.write(buffer_.data(), buffer_.size() - stream_.avail_out);
            } while (stream_.avail_out == 0 || (flush == Z_FINISH && result != Z_STREAM_END));
            if (flush == Z_FINISH) return;
            data += chunk; size -= chunk;
        }
    }
};

class GzipDecoder final : public Source {
public:
    explicit GzipDecoder(Source& in) : in_(in), input_(buffer_size, '\0') {
        if (inflateInit2(&stream_, 15 + 16) != Z_OK) throw Error("failed to initialise gzip");
        fill();
        if (stream_.avail_in < 2 || input_[0] != '\x1f' || input_[1] != '\x8b') throw Error("Not in GZIP format");
    }
    ~GzipDecoder() override { inflateEnd(&stream_); }
    size_t read(char* data, size_t size) override {
        while (!done_ && size) {
            if (!stream_.avail_in && !eof_) fill();
            stream_.next_out = reinterpret_cast<Bytef*>(data);
            stream_.avail_out = static_cast<uInt>(std::min<size_t>(size, 1u << 30));
            const auto before = stream_.avail_out;
            const int result = inflate(&stream_, Z_NO_FLUSH);
            const size_t produced = before - stream_.avail_out;
            if (result == Z_STREAM_END) {
                // GZIPInputStream reads a following member; anything else ends the stream.
                if (!stream_.avail_in && !eof_) fill();
                if (stream_.avail_in >= 2 && stream_.next_in[0] == 0x1f && stream_.next_in[1] == 0x8b) inflateReset(&stream_);
                else done_ = true;
            } else if (result == Z_DATA_ERROR) {
                throw Error(stream_.msg && std::strcmp(stream_.msg, "incorrect data check") && std::strcmp(stream_.msg, "incorrect length check")
                    ? stream_.msg : "Corrupt GZIP trailer");
            } else if (result == Z_BUF_ERROR) {
                if (eof_ && !stream_.avail_in) throw Error("Unexpected end of ZLIB input stream");
            } else if (result != Z_OK) throw Error(stream_.msg ? stream_.msg : "gzip decompression failed");
            if (produced) return produced;
        }
        return 0;
    }
private:
    Source& in_;
    z_stream stream_{};
    std::string input_;
    bool eof_ = false, done_ = false;
    void fill() {
        const auto count = in_.read(input_.data(), input_.size());
        if (!count) eof_ = true;
        stream_.next_in = reinterpret_cast<Bytef*>(input_.data());
        stream_.avail_in = static_cast<uInt>(count);
    }
};

const char* lzma_message(lzma_ret result) {
    // xz-java's exception texts for the same conditions.
    switch (result) {
        case LZMA_FORMAT_ERROR: return "Input is not in the XZ format";
        case LZMA_OPTIONS_ERROR: return "Unsupported options in XZ Stream Header";
        case LZMA_DATA_ERROR: return "Compressed data is corrupt";
        case LZMA_BUF_ERROR: return "Unexpected end of input";
        case LZMA_MEM_ERROR: return "Out of memory";
        case LZMA_MEMLIMIT_ERROR: return "Memory usage limit exceeded";
        case LZMA_UNSUPPORTED_CHECK: return "Unsupported Check ID";
        default: return "XZ stream error";
    }
}
class XzEncoder final : public Encoder {
public:
    explicit XzEncoder(Sink& out) : out_(out), buffer_(buffer_size, '\0') {
        // new XZOutputStream(out, new LZMA2Options()): preset 6, CRC64.
        const auto result = lzma_easy_encoder(&stream_, 6, LZMA_CHECK_CRC64);
        if (result != LZMA_OK) throw Error(lzma_message(result));
    }
    ~XzEncoder() override { lzma_end(&stream_); }
    void write(const char* data, size_t size) override { run(data, size, LZMA_RUN); }
    void finish() override { if (!finished_) { run(nullptr, 0, LZMA_FINISH); finished_ = true; } }
private:
    Sink& out_;
    lzma_stream stream_ = LZMA_STREAM_INIT;
    std::string buffer_;
    bool finished_ = false;
    void run(const char* data, size_t size, lzma_action action) {
        stream_.next_in = reinterpret_cast<const uint8_t*>(data);
        stream_.avail_in = size;
        for (;;) {
            stream_.next_out = reinterpret_cast<uint8_t*>(buffer_.data());
            stream_.avail_out = buffer_.size();
            const auto result = lzma_code(&stream_, action);
            if (result != LZMA_OK && result != LZMA_STREAM_END) throw Error(lzma_message(result));
            out_.write(buffer_.data(), buffer_.size() - stream_.avail_out);
            if (action == LZMA_FINISH ? result == LZMA_STREAM_END : (!stream_.avail_in && stream_.avail_out)) return;
        }
    }
};
class XzDecoder final : public Source {
public:
    explicit XzDecoder(Source& in) : in_(in), input_(buffer_size, '\0') {
        // XZInputStream: concatenated streams and stream padding, no memory limit.
        const auto result = lzma_stream_decoder(&stream_, UINT64_MAX, LZMA_CONCATENATED);
        if (result != LZMA_OK) throw Error(lzma_message(result));
    }
    ~XzDecoder() override { lzma_end(&stream_); }
    size_t read(char* data, size_t size) override {
        while (!done_ && size) {
            if (!stream_.avail_in && !eof_) {
                const auto count = in_.read(input_.data(), input_.size());
                if (!count) eof_ = true;
                stream_.next_in = reinterpret_cast<const uint8_t*>(input_.data());
                stream_.avail_in = count;
            }
            stream_.next_out = reinterpret_cast<uint8_t*>(data);
            stream_.avail_out = size;
            const auto result = lzma_code(&stream_, eof_ ? LZMA_FINISH : LZMA_RUN);
            const size_t produced = size - stream_.avail_out;
            if (result == LZMA_STREAM_END) done_ = true;
            else if (result != LZMA_OK) throw Error(lzma_message(result));
            if (produced) return produced;
        }
        return 0;
    }
private:
    Source& in_;
    lzma_stream stream_ = LZMA_STREAM_INIT;
    std::string input_;
    bool eof_ = false, done_ = false;
};

class ZstdEncoder final : public Encoder {
public:
    explicit ZstdEncoder(Sink& out) : out_(out), context_(ZSTD_createCCtx()), buffer_(ZSTD_CStreamOutSize(), '\0') {
        if (!context_) throw Error("Out of memory");
        // new ZstdOutputStream(out, 3).setWorkers(4)
        check(ZSTD_CCtx_setParameter(context_, ZSTD_c_compressionLevel, 3));
        check(ZSTD_CCtx_setParameter(context_, ZSTD_c_nbWorkers, zstd_workers));
    }
    ~ZstdEncoder() override { ZSTD_freeCCtx(context_); }
    void write(const char* data, size_t size) override {
        ZSTD_inBuffer input{data, size, 0};
        while (input.pos < input.size) {
            ZSTD_outBuffer output{buffer_.data(), buffer_.size(), 0};
            check(ZSTD_compressStream2(context_, &output, &input, ZSTD_e_continue));
            out_.write(buffer_.data(), output.pos);
        }
    }
    void finish() override {
        if (finished_) return;
        ZSTD_inBuffer input{nullptr, 0, 0};
        size_t remaining;
        do {
            ZSTD_outBuffer output{buffer_.data(), buffer_.size(), 0};
            remaining = check(ZSTD_compressStream2(context_, &output, &input, ZSTD_e_end));
            out_.write(buffer_.data(), output.pos);
        } while (remaining);
        finished_ = true;
    }
private:
    Sink& out_;
    ZSTD_CCtx* context_;
    std::string buffer_;
    bool finished_ = false;
    static size_t check(size_t result) {
        if (ZSTD_isError(result)) throw Error(ZSTD_getErrorName(result));
        return result;
    }
};
class ZstdDecoder final : public Source {
public:
    explicit ZstdDecoder(Source& in) : in_(in), context_(ZSTD_createDCtx()), input_(ZSTD_DStreamInSize(), '\0') {
        if (!context_) throw Error("Out of memory");
    }
    ~ZstdDecoder() override { ZSTD_freeDCtx(context_); }
    size_t read(char* data, size_t size) override {
        if (!size) return 0;
        for (;;) {
            if (position_ == filled_ && !eof_) {
                filled_ = in_.read(input_.data(), input_.size());
                position_ = 0;
                if (!filled_) eof_ = true;
            }
            if (position_ == filled_ && eof_ && !pending_) return 0;
            ZSTD_inBuffer input{input_.data(), filled_, position_};
            ZSTD_outBuffer output{data, size, 0};
            const auto result = ZSTD_decompressStream(context_, &output, &input);
            if (ZSTD_isError(result)) throw Error(ZSTD_getErrorName(result));
            position_ = input.pos;
            pending_ = result != 0;
            if (output.pos) return output.pos;
            // zstd-jni ZstdInputStream when the source ends inside a frame.
            if (position_ == filled_ && eof_) {
                if (pending_) throw Error("Read error or truncated source");
                return 0;
            }
        }
    }
private:
    Source& in_;
    ZSTD_DCtx* context_;
    std::string input_;
    size_t position_ = 0, filled_ = 0;
    bool eof_ = false, pending_ = false;
};

class PlainDecoder final : public Source {
public:
    explicit PlainDecoder(Source& in) : in_(in) {}
    size_t read(char* data, size_t size) override { return in_.read(data, size); }
private:
    Source& in_;
};
}
std::unique_ptr<Encoder> compress(Sink& out, Compression compression) {
    switch (compression) {
        case Compression::none: return std::make_unique<PlainEncoder>(out);
        case Compression::gzip: return std::make_unique<GzipEncoder>(out);
        case Compression::xz: return std::make_unique<XzEncoder>(out);
        case Compression::zstd: return std::make_unique<ZstdEncoder>(out);
    }
    throw Error("unknown compression");
}
std::unique_ptr<Source> decompress(Source& in, Compression compression) {
    switch (compression) {
        case Compression::none: return std::make_unique<PlainDecoder>(in);
        case Compression::gzip: return std::make_unique<GzipDecoder>(in);
        case Compression::xz: return std::make_unique<XzDecoder>(in);
        case Compression::zstd: return std::make_unique<ZstdDecoder>(in);
    }
    throw Error("unknown compression");
}
}
