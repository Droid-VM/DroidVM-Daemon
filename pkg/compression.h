// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "io.h"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace droidvm::pkg {
// lib/archive/Compression: the type is the on-disk header value.
enum class Compression { none = 0, gzip = 1, xz = 2, zstd = 3 };
inline const std::vector<const char*> compression_names{"NONE", "GZIP", "XZ", "ZSTD"};
std::optional<Compression> compression_from_type(int type);
const char* compression_name(Compression compression); // enum name, as JSONObject.put writes it
Compression compression_from_name(const std::string& name); // a name from compression_names
// An encoder writing into out; finish() ends the stream (GZIP trailer, XZ index, zstd epilogue).
class Encoder : public Sink {
public:
    virtual void finish() = 0;
};
// TarWriter.wrapCompressionOutput: GZIP level 6, XZ preset 6 with CRC64,
// zstd level 3 with zstd_workers worker threads; NONE passes through.
inline constexpr int zstd_workers = 4;
std::unique_ptr<Encoder> compress(Sink& out, Compression compression);
// TarWriter.wrapCompressionInput: concatenated members/streams/frames are read in turn.
std::unique_ptr<Source> decompress(Source& in, Compression compression);
}
