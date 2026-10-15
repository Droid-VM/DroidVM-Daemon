// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "context.h"
#include "store/json_file.h"
#include <map>
#include <memory>
#include <mutex>

namespace droidvm {
// Persistent configuration ownership; no socket, Android Context or kernel
// network side effects. Runtime activation/deletion will compose this service.
class NetworkConfigService {
public:
    explicit NetworkConfigService(int files_directory, uid_t owner, config::JsonFile::Observer observer = {});
    Json::Value list(const CallContext& caller) const;
    Json::Value get(const CallContext& caller, const std::string& id) const;
    bool exists(const CallContext& caller, const std::string& id) const;
    std::string create(const CallContext& caller, Json::Value value);
    std::string update(const CallContext& caller, Json::Value value);
    bool recovered() const;
    size_t inactive() const;
private:
    struct State {
        Json::Value document;
        std::map<std::string, Json::ArrayIndex> ids;
        size_t inactive = 0;
        bool recovered = false;
    };
    config::JsonFile file_;
    mutable std::mutex state_mutex_;
    std::mutex writer_mutex_;
    std::shared_ptr<const State> state_;
    std::shared_ptr<const State> state() const;
    static std::shared_ptr<State> decode(Json::Value document, bool recovered);
    std::string change(const CallContext& caller, Json::Value value, bool update);
};
}
