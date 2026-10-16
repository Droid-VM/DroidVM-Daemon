// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright DroidVM contributors
// Additional permissions apply; see ADDITIONAL-PERMISSIONS in the repository root.
#include <aidl/cn/classfun/droidvm/display/BnNativeDisplayRootService.h>
#include <android/api-level.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <json/json.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include "broadcast.h"
#include "service_manager.h"
#include "input_probe.h"

namespace {
using namespace aidl::cn::classfun::droidvm::display;
using namespace std::chrono_literals;

struct State {
    std::mutex mutex;
    std::condition_variable changed;
    bool finished = false;
    std::atomic<bool> client_died{false};
    std::atomic<bool> input_checked{false};
    std::atomic<bool> echo_sent{false};
    std::atomic<int> caller_uid{-1};
    std::atomic<bool> real_display_returned{false};
};

// Synthetic protocol checks may additionally target the explicitly isolated VM.
class RemoteFixture final : public BnNativeDisplayRootService {
public:
    RemoteFixture(std::string nonce, std::shared_ptr<State> state, std::string display_service, std::shared_ptr<InputProbe> input)
        : nonce_(std::move(nonce)), state_(std::move(state)), display_service_(std::move(display_service)), input_(std::move(input)), death_(AIBinder_DeathRecipient_new(
            [](void* cookie) {
                (*static_cast<std::shared_ptr<State>*>(cookie))->client_died = true;
            })) {
        AIBinder_DeathRecipient_setOnUnlinked(death_.get(), [](void* cookie) {
            delete static_cast<std::shared_ptr<State>*>(cookie);
        });
    }

    ndk::ScopedAStatus waitForDisplayBinder(const std::string& name,
                                           ndk::SpAIBinder* result) override {
        state_->caller_uid = static_cast<int>(AIBinder_getCallingUid());
        *result = name == nonce_ ? asBinder() : ndk::SpAIBinder();
        if (!display_service_.empty() && name == display_service_) {
            *result = manager_.wait(name.c_str(), 5s);
            state_->real_display_returned = result->get() != nullptr;
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus writeInput(const std::string& vm, const std::string& screen,
                                 int32_t channel, const std::vector<uint8_t>& bytes,
                                 bool* result) override {
        *result = false;
        if (input_ && vm == display_service_) {
            *result = input_->write(screen, channel, bytes);
            return ndk::ScopedAStatus::ok();
        }
        if (vm != nonce_) return ndk::ScopedAStatus::ok();
        if (channel == -10) {
            *result = state_->client_died;
        } else if (channel == -11 && state_->client_died) {
            std::lock_guard lock(state_->mutex);
            state_->finished = true;
            *result = true;
            state_->changed.notify_all();
        } else {
            *result = screen == "screen-\xe8\xbf\x81\xe7\xa7\xbb" && channel == 3 &&
                bytes == std::vector<uint8_t>({0, 1, 0x7f, 0x80, 0xff, 0, 0, 1});
            if (*result) state_->input_checked = true;
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setKeyboardGrab(const std::string& vm, const std::string&,
                                      bool grab, const ndk::SpAIBinder& token,
                                      int32_t* count) override {
        *count = 0;
        if (vm != nonce_) return ndk::ScopedAStatus::ok();
        std::lock_guard lock(token_mutex_);
        if (token_.get()) {
            AIBinder_unlinkToDeath(token_.get(), death_.get(), cookie_);
            token_ = {};
            cookie_ = nullptr;
        }
        if (grab && token.get() && AIBinder_isRemote(token.get())) {
            auto* cookie = new std::shared_ptr<State>(state_);
            auto status = AIBinder_linkToDeath(token.get(), death_.get(), cookie);
            // onUnlinked owns the cookie even when linkToDeath returns an error.
            if (status != STATUS_OK) return ndk::ScopedAStatus::fromStatus(status);
            token_ = token;
            cookie_ = cookie;
            *count = 2;
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setKeyEcho(const std::string& vm, const std::string&,
                                const std::shared_ptr<IPhysicalKeyEcho>& echo) override {
        if (vm == nonce_ && echo) {
            auto status = echo->onKeys({1, 30, 125}, {1, 0, 1});
            if (!status.isOk()) return status;
            status = echo->onLeds(7, 2);
            if (!status.isOk()) return status;
            state_->echo_sent = true;
        }
        return ndk::ScopedAStatus::ok();
    }
private:
    std::string nonce_;
    std::shared_ptr<State> state_;
    std::string display_service_;
    ServiceManager manager_;
    std::shared_ptr<InputProbe> input_;
    std::mutex token_mutex_;
    ndk::SpAIBinder token_;
    void* cookie_ = nullptr; // opaque unlink identity; never dereferenced after link
    ndk::ScopedAIBinder_DeathRecipient death_;
};

}

void run_broadcast_probe(AIBinder* activity, const std::string& nonce, const std::string& display_service,
                         const std::string& input_directory, Json::Value& report) {
    const auto profile = droidvm::platform::broadcast_profile();
    char fingerprint[PROP_VALUE_MAX]{};
    __system_property_get("ro.build.fingerprint", fingerprint);
    if (nonce.size() != 32 || nonce.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("nonce must be 32 lowercase hex digits");
    report["fingerprint"] = fingerprint;
    report["uid"] = static_cast<Json::UInt>(getuid());
    std::ifstream context("/proc/self/attr/current");
    std::string label;
    if (std::getline(context, label, '\0')) report["selinux_context"] = label;
    if (!droidvm::platform::start_binder_pool()) throw std::runtime_error("native Binder thread pool unavailable");
    std::shared_ptr<InputProbe> input_probe;
    if (!input_directory.empty()) {
        if (display_service.empty()) throw std::runtime_error("input probe requires isolated display service");
        input_probe = std::make_shared<InputProbe>(input_directory);
        input_probe->wait_for_guest();
    }
    auto state = std::make_shared<State>();
    auto broker = ndk::SharedRefBase::make<RemoteFixture>(nonce, state, display_service, input_probe);
    droidvm::platform::send_binder_broadcast(activity, broker->asBinder().get(), nonce, profile, report);
    std::unique_lock lock(state->mutex);
    if (!state->changed.wait_for(lock, 30s, [&] { return state->finished; }))
        throw std::runtime_error("timed out waiting for Java contract checks");
    report["client_uid"] = state->caller_uid.load();
    report["input_checked"] = state->input_checked.load();
    report["echo_sent"] = state->echo_sent.load();
    report["client_death_received"] = state->client_died.load();
    report["cross_process_tested"] = true;
    report["synthetic_fixture_only"] = display_service.empty();
    report["synthetic_input_fixture"] = true;
    report["real_display_returned"] = state->real_display_returned.load();
    if (input_probe) input_probe->report(report);
    if (!display_service.empty() && !state->real_display_returned)
        throw std::runtime_error("real display service was not returned");
    if (!state->input_checked || !state->echo_sent || !state->client_died || state->caller_uid < 10000)
        throw std::runtime_error("incomplete cross-process checks");
}
