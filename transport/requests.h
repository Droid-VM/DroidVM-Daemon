// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "dispatcher.h"
#include "common/fd.h"
#include <map>
#include <mutex>
#include <vector>

namespace droidvm {
class RequestQueue {
public:
    struct Completion { uint64_t client; std::string frame; size_t reservation; };
    explicit RequestQueue(RequestDispatcher& dispatcher);
    ~RequestQueue();
    int fd() const { return ready_.get(); }
    void submit(uint64_t client, const ClientSession& session, std::string command, Json::Value request, size_t input_bytes);
    std::vector<Completion> drain();
    void release(const Completion& completion);
private:
    RequestDispatcher& dispatcher_;
    Fd ready_;
    std::mutex mutex_;
    std::vector<Completion> done_;
    std::map<uint64_t, size_t> clients_;
    size_t pending_ = 0, reserved_ = 0;
};
}
