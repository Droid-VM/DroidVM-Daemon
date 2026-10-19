// SPDX-License-Identifier: GPL-3.0-or-later
// Extracted from the App vkprobe JNI implementation.
#include "vulkan_blit_probe.h"
#include <algorithm>
#include <cstring>
#include <dlfcn.h>
#include <memory>
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>

namespace droidvm::vm {
std::optional<std::vector<std::string>> missing_system_blit_extensions() {
    const auto close = [](void* handle) { if (handle) dlclose(handle); };
    std::unique_ptr<void, decltype(close)> library(dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL), close);
    if (!library) return {};
    const auto gipa = reinterpret_cast<PFN_vkGetInstanceProcAddr>(dlsym(library.get(), "vkGetInstanceProcAddr"));
    if (!gipa) return {};
    const auto create = reinterpret_cast<PFN_vkCreateInstance>(gipa(VK_NULL_HANDLE, "vkCreateInstance"));
    if (!create) return {};
    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "droidvm-vkprobe";
    app.apiVersion = VK_API_VERSION_1_0;
    VkInstanceCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    info.pApplicationInfo = &app;
    VkInstance instance = VK_NULL_HANDLE;
    if (create(&info, nullptr, &instance) != VK_SUCCESS || instance == VK_NULL_HANDLE) return {};
    const auto destroy = reinterpret_cast<PFN_vkDestroyInstance>(gipa(instance, "vkDestroyInstance"));
    if (!destroy) return {};
    const auto dispose = [destroy](VkInstance value) { destroy(value, nullptr); };
    std::unique_ptr<std::remove_pointer_t<VkInstance>, decltype(dispose)> held(instance, dispose);
    const auto devices = reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(gipa(instance, "vkEnumeratePhysicalDevices"));
    const auto extensions = reinterpret_cast<PFN_vkEnumerateDeviceExtensionProperties>(gipa(instance, "vkEnumerateDeviceExtensionProperties"));
    if (!devices || !extensions) return {};
    uint32_t count = 0;
    if (devices(instance, &count, nullptr) != VK_SUCCESS || !count || count > 64) return {};
    std::vector<VkPhysicalDevice> physical(count);
    if (devices(instance, &count, physical.data()) != VK_SUCCESS || count > physical.size()) return {};
    physical.resize(count);
    std::optional<std::vector<std::string>> best;
    for (const auto device : physical) {
        uint32_t size = 0;
        if (extensions(device, nullptr, &size, nullptr) != VK_SUCCESS || size > 4096) return {};
        std::vector<VkExtensionProperties> properties(size);
        if (size && (extensions(device, nullptr, &size, properties.data()) != VK_SUCCESS || size > properties.size())) return {};
        properties.resize(size);
        for (const auto& property : properties)
            if (!std::memchr(property.extensionName, '\0', sizeof(property.extensionName))) return {};
        std::vector<std::string> missing;
        for (const auto required : blit_extensions)
            if (std::none_of(properties.begin(), properties.end(), [required](const auto& property) {
                    return required == property.extensionName;
                })) missing.emplace_back(required);
        if (missing.empty()) return missing;
        if (!best || missing.size() < best->size()) best = std::move(missing);
    }
    return best;
}
}
