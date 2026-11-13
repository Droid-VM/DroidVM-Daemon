// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <memory>

namespace droidvm {
// Owned by the independent display sentinel. Preparation happens before Android
// is changed; start happens only after the old framework has exited.
class AndroidWifiSession {
public:
    virtual ~AndroidWifiSession() = default;
    virtual void start() = 0;
    virtual void check() = 0; // throws on child exit, lost lease or changed network
    virtual void stop() = 0;
};
Json::Value android_wifi_plan(); // null when no Wi-Fi interface is associated
std::unique_ptr<AndroidWifiSession> android_wifi_prepare(const Json::Value& plan);
// Restrict the persisted supplicant configuration to one unambiguous SSID.
// Never returns credentials, and never includes configuration text in errors.
bool android_wifi_config_matches(const std::string& config, const std::string& ssid);
bool android_wifi_lease_matches(const Json::Value& plan, const std::string& event, unsigned& lease);
}
