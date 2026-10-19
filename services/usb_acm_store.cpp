// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb_acm_store.h"
#include "store/json_file.h"
namespace droidvm {
UsbAcmOptions usb_acm_store(int directory, uid_t owner, vm::AcmControl& pool) {
    auto file = std::make_shared<config::JsonFile>(directory, "usb-acm.json", owner, config::JsonFile::Observer{}, 4096, config::JsonSyntax::strict);
    UsbAcmOptions out; out.pool = &pool;
    out.load = [file]() -> std::optional<UsbAcmLoaded> {
        const auto loaded = file->load();
        return loaded ? std::optional(UsbAcmLoaded{loaded->value, loaded->recovered}) : std::nullopt;
    };
    out.save = [file](const Json::Value& document) {
        try { file->save(document); return UsbAcmSave::saved; }
        catch (const config::CommitError& error) { return error.installed ? UsbAcmSave::installed_uncertain : UsbAcmSave::not_saved; }
        catch (const std::exception&) { return UsbAcmSave::not_saved; }
    }; return out;
}
}
