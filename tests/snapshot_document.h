// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "contracts.h"

namespace droidvm::test {
inline std::string read_document(TaskService& service, const CallContext& caller, SnapshotPage page, Json::Value& metadata) {
    const auto cursor = page.cursor;
    std::string result;
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t rows = 0;
    for (;;) {
        check(page.cursor.epoch == cursor.epoch && page.cursor.sequence == cursor.sequence, "all document pages retain fixed cursor");
        for (const auto& encoded : page.items) {
            auto row = wire::parse(encoded);
            if (!rows++) {
                metadata = row;
                check(row["type"] == "metadata" && row["encoding"] == "base64-json", "document header encoding");
                continue;
            }
            check(row["type"] == "chunk" && row["offset"].asUInt64() == result.size(), "document chunk byte continuity");
            auto data = row["data"].asString();
            check(data.size() % 4 == 0, "base64 quartet alignment");
            for (size_t i = 0; i < data.size(); i += 4) {
                uint32_t value = 0;
                for (size_t j = 0; j < 4; ++j) {
                    auto digit = data[i + j] == '=' ? 0 : alphabet.find(data[i + j]);
                    check(digit < 64, "base64 alphabet"); value = value * 64 + static_cast<uint32_t>(digit);
                }
                result += static_cast<char>(value >> 16);
                if (data[i + 2] != '=') result += static_cast<char>(value >> 8);
                if (data[i + 3] != '=') result += static_cast<char>(value);
            }
        }
        if (!page.next) break;
        page = service.snapshot_page(caller, page.id, *page.next, 128u << 10);
    }
    check(rows == page.total && metadata["bytes"].asUInt64() == result.size(), "complete document reconstructed");
    return result;
}
}
