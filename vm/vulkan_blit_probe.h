// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace droidvm::vm {
// crosvm Android display bridge's device extension set. Shared by App and Web.
inline constexpr std::array<std::string_view, 7> blit_extensions{
    "VK_EXT_external_memory_dma_buf", "VK_EXT_image_drm_format_modifier",
    "VK_ANDROID_external_memory_android_hardware_buffer", "VK_KHR_external_memory_fd",
    "VK_EXT_queue_family_foreign", "VK_KHR_external_semaphore", "VK_KHR_external_semaphore_fd"
};
// Unknown on any unsuccessful/incomplete enumeration. No logical device or
// Surface is created. An empty result proves extension presence, not rendering.
std::optional<std::vector<std::string>> missing_system_blit_extensions();
}
