// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "io.h"
#include <functional>
#include <string>

namespace droidvm::pkg {
// lib/archive/TarWriter: ustar headers with mode 0644, uid/gid 0 and the
// current time; sizes past 12 octal digits use GNU base-256. A name longer
// than 100 UTF-16 units is preceded by a "./@LongLink" regular entry.
class TarWriter {
public:
    explicit TarWriter(Sink& out) : out_(out) {}
    using Content = std::function<void(Sink& out)>;
    void entry(const std::string& name, int64_t size, const Content& content);
    void entry(const std::string& name, std::string_view bytes);
    void close(); // two zero blocks
private:
    Sink& out_;
    bool closed_ = false;
    void header(const std::string& name, int64_t size, char type);
};
// lib/archive/TarReader: regular files go to the handler (type '0' or NUL),
// a GNU 'L' entry renames the next one, everything else is skipped.
class TarReader {
public:
    explicit TarReader(Source& in) : in_(in) {}
    using Handler = std::function<void(const std::string& name, int mode, int64_t size, Source& content)>;
    void for_each(const Handler& handler);
private:
    Source& in_;
    bool eof_ = false;
    bool block(char* header);
};
}
