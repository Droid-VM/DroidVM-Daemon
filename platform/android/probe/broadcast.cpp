// SPDX-License-Identifier: GPL-3.0-or-later
#include "broadcast.h"
#include "broadcast_profile.h"
#include <android/api-level.h>
#include <android/binder_auto_utils.h>
#include <android/binder_parcel.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace droidvm::platform {
namespace {
void checked(binder_status_t status) {
    if (status != STATUS_OK) throw std::runtime_error("Binder status " + std::to_string(status));
}
void integer(AParcel* p, int32_t value) { checked(AParcel_writeInt32(p, value)); }
void string(AParcel* p, const std::string& value) {
    checked(AParcel_writeString(p, value.data(), static_cast<int32_t>(value.size())));
}
void null_string(AParcel* p) { checked(AParcel_writeString(p, nullptr, -1)); }
void scalar_words(AParcel* p, const std::string& hex) {
    if (hex.size() % 8 != 0 || hex.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("invalid scalar profile");
    for (size_t offset = 0; offset < hex.size(); offset += 8) {
        uint32_t word = 0;
        for (unsigned byte = 0; byte < 4; ++byte)
            word |= std::stoul(hex.substr(offset + byte * 2, 2), nullptr, 16) << (byte * 8);
        integer(p, static_cast<int32_t>(word));
    }
}
// Bundle lengths exclude their length and magic words. Only overwrite the integer
// placeholder, never the Binder object offsets tracked by Parcel itself.
template<class Write> void bundle(AParcel* p, const std::string& trailer, Write write) {
    const auto length_pos = AParcel_getDataPosition(p);
    integer(p, -1);
    integer(p, 0x4c444e42);
    const auto start = AParcel_getDataPosition(p);
    write();
    const auto end = AParcel_getDataPosition(p);
    checked(AParcel_setDataPosition(p, length_pos));
    integer(p, end - start);
    checked(AParcel_setDataPosition(p, end));
    // This ROM appends metadata outside the Bundle length. A parent's length
    // must include its child's trailer; the parent's own trailer is excluded.
    scalar_words(p, trailer);
}
}
Json::Value broadcast_profile() {
    Json::Value profile;
    std::istringstream input(kBroadcastProfile);
    input >> profile;
    char fingerprint[PROP_VALUE_MAX]{};
    __system_property_get("ro.build.fingerprint", fingerprint);
    if (android_get_device_api_level() != profile["sdk"].asInt() || fingerprint != profile["fingerprint"].asString())
        throw std::runtime_error("no verified broadcast profile for this firmware");
    return profile;
}
Json::Value client_broadcast_profile(const Json::Value& client) {
    const auto hex = [&](const char* key, size_t limit) {
        const auto& value = client[key];
        if (!value.isString() || value.asString().size() % 8 || value.asString().size() > limit ||
                value.asString().find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error(std::string("invalid client profile ") + key);
        return value;
    };
    if (!client.isObject() || !client["sdk"].isInt() || client["sdk"].asInt() != android_get_device_api_level())
        throw std::runtime_error("client profile is for another SDK");
    const auto& code = client["broadcast_transaction"];
    if (!code.isUInt() || code.asUInt() < 1 || code.asUInt() > 0xffffff || !client["extras_offset"].isUInt() ||
            !client["target_package"].isString() || client["target_package"].asString().empty())
        throw std::runtime_error("invalid client profile");
    Json::Value profile;
    profile["broadcast_transaction"] = code;
    profile["extras_offset"] = client["extras_offset"];
    profile["empty_intent_hex"] = hex("empty_intent_hex", 4096);
    profile["bundle_trailer_hex"] = hex("bundle_trailer_hex", 64);
    profile["target_package"] = client["target_package"];
    return profile;
}
bool start_binder_pool() {
    // Thread-pool management, like ServiceManager, is exported by Android but
    // is not in the public NDK. Resolve it explicitly and fail closed if absent.
    static std::once_flag once;
    static bool started = false;
    std::call_once(once, [] {
        auto set_threads = reinterpret_cast<bool (*)(uint32_t)>(dlsym(RTLD_DEFAULT, "ABinderProcess_setThreadPoolMaxThreadCount"));
        auto start_threads = reinterpret_cast<void (*)()>(dlsym(RTLD_DEFAULT, "ABinderProcess_startThreadPool"));
        if (!set_threads || !start_threads || !set_threads(4)) return;
        start_threads();
        started = true;
    });
    return started;
}
namespace {
// Parcel.writeString8: length, UTF-8 bytes, NUL, zero padding to 4 bytes.
std::string string8_hex(const std::string& text) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string bytes(4, '\0');
    const auto length = static_cast<uint32_t>(text.size());
    for (int i = 0; i < 4; ++i) bytes[i] = static_cast<char>((length >> (8 * i)) & 255);
    bytes += text;
    bytes += '\0';
    while (bytes.size() % 4) bytes += '\0';
    std::string hex;
    for (const auto byte : bytes) { hex += digits[static_cast<unsigned char>(byte) >> 4]; hex += digits[static_cast<unsigned char>(byte) & 15]; }
    return hex;
}
}
void send_binder_broadcast(AIBinder* activity, AIBinder* broker, const std::string& nonce,
                           const Json::Value& profile, Json::Value& report, const std::string& package) {
    if (!activity) throw std::runtime_error("activity service unavailable");
    auto* clazz = AIBinder_Class_define("android.app.IActivityManager",
        [](void* p) { return p; }, [](void*) {},
        [](AIBinder*, transaction_code_t, const AParcel*, AParcel*) -> binder_status_t {
            return STATUS_UNKNOWN_TRANSACTION;
        });
    if (!AIBinder_associateClass(activity, clazz)) throw std::runtime_error("activity descriptor mismatch");
    ndk::ScopedAParcel request, response;
    checked(AIBinder_prepareTransaction(activity, request.getR()));
    auto* p = request.get();
    checked(AParcel_writeStrongBinder(p, nullptr)); // caller
    null_string(p); // callingFeatureId
    integer(p, 1); // Intent presence

    // The empty Intent is captured by PlatformProfileTest on this exact firmware.
    // It has no Binder/FD objects. Copy its scalar words, inserting the live Bundle
    // through NDK APIs so the Binder object table is maintained by libbinder.
    auto hex = profile["empty_intent_hex"].asString();
    auto extras = profile["extras_offset"].asUInt();
    const auto target = profile.get("target_package", "cn.classfun.droidvm.migration.test").asString();
    if (!package.empty() && package != target) {
        // The captured Intent names exactly one package, before the extras slot.
        const auto captured = string8_hex(target), wanted = string8_hex(package);
        const auto at = hex.find(captured);
        if (at == std::string::npos || at % 8 || at / 2 >= extras || hex.find(captured, at + 1) != std::string::npos)
            throw std::runtime_error("broadcast profile has no target package to replace");
        hex.replace(at, captured.size(), wanted);
        extras = static_cast<unsigned>(extras + wanted.size() / 2 - captured.size() / 2);
    }
    const auto trailer = profile["bundle_trailer_hex"].asString();
    if (!profile["bundle_trailer_hex"].isString() || extras % 4 ||
        extras * 2 + 8 > hex.size() || hex.substr(extras * 2, 8) != "ffffffff")
        throw std::runtime_error("invalid Bundle profile");
    for (size_t offset = 0; offset < hex.size() / 2; offset += 4) {
        if (offset == extras && broker) {
            bundle(p, trailer, [&] {
                integer(p, 1);
                string(p, "extra.bundle"); integer(p, 3); // VAL_BUNDLE
                bundle(p, trailer, [&] {
                    integer(p, 2);
                    // Java ArrayMap is ordered by signed key hash: binder, nonce.
                    string(p, "binder"); integer(p, 15); // VAL_IBINDER
                    checked(AParcel_writeStrongBinder(p, broker));
                    string(p, "nonce"); integer(p, 0); // VAL_STRING
                    string(p, nonce);
                });
            });
        } else {
            scalar_words(p, hex.substr(offset * 2, 8));
        }
    }
    null_string(p); // resolvedType
    checked(AParcel_writeStrongBinder(p, nullptr)); // resultTo
    integer(p, 0); // resultCode
    null_string(p); // resultData
    integer(p, 0); // resultExtras presence
    integer(p, -1); integer(p, -1); integer(p, -1); // permissions / exclusions
    integer(p, -1); // OP_NONE
    integer(p, 0); // options presence
    integer(p, 0); integer(p, 0); integer(p, 0); // ordered, sticky, user 0
    checked(AIBinder_transact(activity, profile["broadcast_transaction"].asUInt(),
                             request.getR(), response.getR(), 0));
    ndk::ScopedAStatus status;
    checked(AParcel_readStatusHeader(response.get(), status.getR()));
    if (!status.isOk()) throw std::runtime_error(status.getDescription());
    int32_t result = -1;
    checked(AParcel_readInt32(response.get(), &result));
    report["broadcast_result"] = result;
    if (result != 0) throw std::runtime_error("broadcast rejected");
}
}
