// SPDX-License-Identifier: GPL-3.0-or-later
#include "display_broker.h"
#include "broadcast.h"
#include "service_manager.h"
#include <aidl/cn/classfun/droidvm/display/BnNativeDisplayRootService.h>
#include <chrono>
#include <thread>

namespace droidvm::platform {
namespace {
using namespace aidl::cn::classfun::droidvm::display;
using namespace std::chrono_literals;
constexpr const char* name_prefix = "droidvm_disp_";

// NativeDisplay.vmIdFromServiceName: empty when the name is not ours.
std::string vm_of(const std::string& service) {
    if (!service.starts_with(name_prefix)) return {};
    const auto rest = service.substr(std::string_view(name_prefix).size());
    for (const char* screen : {"gpu-0", "simplefb"}) {
        const auto suffix = std::string("_") + screen;
        if (rest.size() >= suffix.size() && rest.ends_with(suffix)) return rest.substr(0, rest.size() - suffix.size());
    }
    return {};
}

// The console's grab token: death releases its grab like an IBinder.DeathRecipient.
class TokenOwner final : public input::KeyboardGrab::Owner {
public:
    explicit TokenOwner(ndk::SpAIBinder token) : token_(std::move(token)), recipient_(AIBinder_DeathRecipient_new(died)) {
        AIBinder_DeathRecipient_setOnUnlinked(recipient_.get(), [](void* cookie) { delete static_cast<Cookie*>(cookie); });
    }
    ~TokenOwner() override { unlink(); }
    bool link(std::function<void()> on_death) override {
        std::lock_guard lock(mutex_);
        if (cookie_) return true;
        auto* cookie = new Cookie{std::move(on_death)};
        // onUnlinked owns the cookie even when linkToDeath fails.
        if (AIBinder_linkToDeath(token_.get(), recipient_.get(), cookie) != STATUS_OK) return false;
        cookie_ = cookie;
        return true;
    }
    void unlink() override {
        std::lock_guard lock(mutex_);
        if (!cookie_) return;
        AIBinder_unlinkToDeath(token_.get(), recipient_.get(), cookie_);
        cookie_ = nullptr;
    }
private:
    struct Cookie { std::function<void()> died; };
    static void died(void* cookie) {
        // The grab manager may hold its lock while linking: never call back inline.
        auto callback = static_cast<Cookie*>(cookie)->died;
        std::thread([callback] { if (callback) callback(); }).detach();
    }
    ndk::SpAIBinder token_;
    ndk::ScopedAIBinder_DeathRecipient recipient_;
    std::mutex mutex_;
    Cookie* cookie_ = nullptr;
};

class Broker final : public BnNativeDisplayRootService {
public:
    explicit Broker(DisplayBroker::Hooks hooks) : hooks_(std::move(hooks)) {}
    ndk::ScopedAStatus waitForDisplayBinder(const std::string& name, ndk::SpAIBinder* result) override {
        *result = ndk::SpAIBinder();
        if (!manager_.available()) return ndk::ScopedAStatus::ok();
        *result = manager_.find(name.c_str());
        if (result->get()) return ndk::ScopedAStatus::ok();
        // A stopped VM never registers; unknown names are not ours to judge.
        const auto vm = vm_of(name);
        if (!vm.empty() && hooks_.state) {
            const auto state = hooks_.state(vm);
            if (state && *state != "RUNNING" && *state != "STARTING" && *state != "REBOOTING") {
                hooks_.log("INFO", "'" + name + "': VM not running, nothing to wait for");
                return ndk::ScopedAStatus::ok();
            }
        }
        // checkService polling: waitForService cannot be cancelled and leaks a thread per stopped VM.
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(200ms);
            *result = manager_.find(name.c_str());
            if (result->get()) return ndk::ScopedAStatus::ok();
        }
        hooks_.log("WARN", "'" + name + "' not found - is crosvm running with --android-display-service " + name + "?");
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus writeInput(const std::string& vm, const std::string& screen, int32_t channel,
                                  const std::vector<uint8_t>& data, bool* result) override {
        *result = !vm.empty() && !data.empty() && hooks_.write_input &&
            hooks_.write_input(vm, screen, channel, std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setKeyboardGrab(const std::string& vm, const std::string& screen, bool grab,
                                       const ndk::SpAIBinder& token, int32_t* count) override {
        *count = 0;
        if (!hooks_.keyboard) return ndk::ScopedAStatus::ok();
        if (!grab || vm.empty()) {
            if (!vm.empty()) hooks_.keyboard->release_for(vm, screen);
            else hooks_.keyboard->release("console released it");
            return ndk::ScopedAStatus::ok();
        }
        *count = hooks_.keyboard->request(vm, screen, token.get() ? std::make_shared<TokenOwner>(token) : nullptr);
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setKeyEcho(const std::string& vm, const std::string& screen,
                                  const std::shared_ptr<IPhysicalKeyEcho>& echo) override {
        if (vm.empty() || !hooks_.keyboard) return ndk::ScopedAStatus::ok();
        std::shared_ptr<input::KeyboardGrab::Echo> bridge;
        if (echo) {
            bridge = std::make_shared<input::KeyboardGrab::Echo>();
            bridge->keys = [echo](const std::vector<int>& codes, const std::vector<int>& values) {
                if (!echo->onKeys(std::vector<int32_t>(codes.begin(), codes.end()), std::vector<int32_t>(values.begin(), values.end())).isOk())
                    throw std::runtime_error("key echo gone");
            };
            bridge->leds = [echo](int known, int on) {
                if (!echo->onLeds(known, on).isOk()) throw std::runtime_error("key echo gone");
            };
        }
        hooks_.keyboard->set_echo(vm, screen, std::move(bridge));
        return ndk::ScopedAStatus::ok();
    }
private:
    DisplayBroker::Hooks hooks_;
    ServiceManager manager_;
};
}
struct DisplayBroker::Impl {
    Hooks hooks;
    std::mutex mutex;
    std::shared_ptr<Broker> broker;
};
DisplayBroker::DisplayBroker(Hooks hooks) : impl_(std::make_unique<Impl>()) { impl_->hooks = std::move(hooks); }
DisplayBroker::~DisplayBroker() = default;
void DisplayBroker::attach(const std::string& nonce) {
    std::lock_guard lock(impl_->mutex);
    try {
        if (!start_binder_pool()) throw std::runtime_error("native Binder thread pool unavailable");
        if (!impl_->broker) impl_->broker = ndk::SharedRefBase::make<Broker>(impl_->hooks);
        ServiceManager manager;
        if (!manager.available()) throw std::runtime_error("no system context; cannot broadcast display binder");
        const auto activity = manager.find("activity");
        Json::Value report;
        send_binder_broadcast(activity.get(), impl_->broker->asBinder().get(), nonce, broadcast_profile(), report, impl_->hooks.package);
        impl_->hooks.log("INFO", "broadcast native-display binder (nonce=" + nonce + ")");
    } catch (const std::exception& error) {
        impl_->hooks.log("ERROR", std::string("native-display binder broadcast failed: ") + error.what());
    }
}
}
