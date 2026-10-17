// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <android/binder_ibinder.h>
#include <json/json.h>
#include <string>

namespace droidvm::platform {
// The verified IActivityManager.broadcastIntent profile for this firmware;
// throws when the running build has none (see profiles/warsaw-api37.json).
Json::Value broadcast_profile();
// A profile the UI captured on this firmware (BroadcastProfile.java), for
// builds without a verified one. Throws unless it is well formed for this SDK.
Json::Value client_broadcast_profile(const Json::Value& client);
// Sends NATIVE_DISPLAY_BINDER to the app with {binder, nonce} nested in
// extra.bundle, as NativeDisplayBinder.broadcast does through Context. The
// profile's Intent targets the test package; package replaces it when set.
void send_binder_broadcast(AIBinder* activity, AIBinder* broker, const std::string& nonce,
                           const Json::Value& profile, Json::Value& report, const std::string& package = {});
// ABinderProcess_setThreadPoolMaxThreadCount + startThreadPool, once.
bool start_binder_pool();
}
