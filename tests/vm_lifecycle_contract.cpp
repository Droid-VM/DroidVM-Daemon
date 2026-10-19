// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise shared admission rules without launching a VMM or writing host config.
#include "services/vm_lifecycle.h"
#include <iostream>

using namespace droidvm;
namespace {
const CallContext browser{"web:browser-a", true, true, true};
void require(bool value) { if (!value) throw std::runtime_error("VM lifecycle contract failed"); }
template<class Function> void rejects(ErrorCode code, Function function) {
    try { function(); } catch (const ServiceError& error) { require(error.code() == code); return; }
    throw std::runtime_error("Expected lifecycle rejection");
}
struct Fixture {
    std::shared_ptr<VmConfigSnapshot> current = std::make_shared<VmConfigSnapshot>();
    size_t reads = 0, confirmations = 0, starts = 0;
    bool admit = true, protection = false, confirm = true, throw_start = false, confirm_conflict = false;
    ConfiguredVmStart seen;
    Json::Value definition;
    VmLifecycleService service{VmLifecycleService::Dependencies{
        [this](const CallContext& caller) -> VmLifecycleService::Snapshot {
            require(caller.principal == browser.principal); ++reads; return current;
        },
        [this](const CallContext& caller, const VmLifecycleService::Snapshot& observed) -> VmLifecycleService::Snapshot {
            require(caller.principal == browser.principal && observed == current); ++confirmations;
            if (confirm_conflict) throw ServiceError(ErrorCode::conflict, "Another configuration writer committed");
            auto next = std::make_shared<VmConfigSnapshot>(*observed);
            next->revision = "confirmed-revision"; next->durability_uncertain = !confirm;
            current = next; return next;
        },
        [this](const Json::Value& row) { require(row["id"] == "vm-a"); return protection; },
        [this](const CallContext& caller, const ConfiguredVmStart& request, const Json::Value& row) {
            require(caller.principal == browser.principal); ++starts; seen = request; definition = row;
            if (throw_start) throw std::runtime_error("unknown runtime outcome");
            return admit;
        }
    }};
    Fixture() {
        current->revision = "observed-revision";
        current->document["vms"] = Json::Value(Json::arrayValue);
        Json::Value row; row["id"] = "vm-a"; row["name"] = "observed"; row["opaque-extension"] = 7;
        current->document["vms"].append(row);
    }
    ConfiguredVmStart request() { return {"observed-revision", "vm-a", "image boot title", Json::Value(), true}; }
};
size_t passed = 0;
template<class Function> void test(const char* name, Function run) { run(); ++passed; std::cout << "PASS " << name << '\n'; }
}
int main() {
    try {
        test("browser identity and exact observed definition reach existing runtime admission", [] {
            Fixture f; auto request = f.request(); request.observed = vm::Observation{"observed-runtime", 9007199254740993ULL};
            const auto result = f.service.start(browser, request);
            require(result.vm_id == request.vm_id && result.revision == request.revision && result.durable_revision.empty());
            require(f.reads == 1 && f.confirmations == 0 && f.starts == 1);
            require(f.definition == f.current->document["vms"][0] && f.seen.boot_entry == request.boot_entry && f.seen.clear_logs.value_or(false));
            require(f.seen.observed == request.observed);
        });
        test("authentication and administrator authority precede config or runtime access", [] {
            Fixture f; auto caller = browser; caller.authenticated = false;
            rejects(ErrorCode::unauthenticated, [&] { f.service.start(caller, f.request()); });
            caller = browser; caller.administrator = false;
            rejects(ErrorCode::permission_denied, [&] { f.service.start(caller, f.request()); });
            caller = browser; caller.principal.clear();
            rejects(ErrorCode::permission_denied, [&] { f.service.start(caller, f.request()); });
            require(f.reads == 0 && f.starts == 0);
        });
        test("omitted log preference and explicit false retain distinct meanings", [] {
            Fixture f; auto request = f.request(); request.clear_logs.reset();
            f.service.start(browser, request); require(!f.seen.clear_logs.has_value());
            request.clear_logs = false; f.service.start(browser, request);
            require(f.seen.clear_logs.has_value() && !*f.seen.clear_logs);
        });
        test("changed revision never causes a silent reload rebase or start", [] {
            Fixture f; f.current->revision = "newer"; f.current->durability_uncertain = true;
            rejects(ErrorCode::conflict, [&] { f.service.start(browser, f.request()); });
            require(f.reads == 1 && f.confirmations == 0 && f.starts == 0);
        });
        test("durability confirmation keeps the observed document and reports both revisions", [] {
            Fixture f; f.current->durability_uncertain = true; const auto document = f.current->document;
            const auto result = f.service.start(browser, f.request());
            require(result.revision == "observed-revision" && result.durable_revision == "confirmed-revision");
            require(f.confirmations == 1 && f.starts == 1 && f.current->document == document);
        });
        test("uncertain durability never launches and is never retried", [] {
            Fixture f; f.current->durability_uncertain = true; f.confirm = false;
            rejects(ErrorCode::commit_uncertain, [&] { f.service.start(browser, f.request()); });
            require(f.confirmations == 1 && f.starts == 0);
        });
        test("a competing writer during durability confirmation is never rebased", [] {
            Fixture f; f.current->durability_uncertain = true; f.confirm_conflict = true;
            rejects(ErrorCode::conflict, [&] { f.service.start(browser, f.request()); });
            require(f.reads == 1 && f.confirmations == 1 && f.starts == 0);
        });
        test("invalid options fail before persistence or launch", [] {
            Fixture f; auto request = f.request(); request.boot_entry.assign((64u << 10) + 1, 'x');
            rejects(ErrorCode::invalid_argument, [&] { f.service.start(browser, request); });
            request = f.request(); request.overrides = Json::Value(Json::arrayValue);
            rejects(ErrorCode::invalid_argument, [&] { f.service.start(browser, request); });
            request = f.request(); request.revision.clear();
            rejects(ErrorCode::invalid_argument, [&] { f.service.start(browser, request); });
            require(f.reads == 0 && f.starts == 0 && f.confirmations == 0);
        });
        test("missing target and unsupported protection override cannot reach runtime", [] {
            Fixture f; auto request = f.request(); request.vm_id = "missing";
            rejects(ErrorCode::not_found, [&] { f.service.start(browser, request); });
            request = f.request(); request.overrides["pseudo_unprotected"] = true;
            rejects(ErrorCode::invalid_argument, [&] { f.service.start(browser, request); });
            require(f.starts == 0);
            f.protection = true; f.service.start(browser, request);
            require(f.starts == 1 && f.seen.overrides == request.overrides);
        });
        test("runtime refusal and unknown outcome never resubmit a start", [] {
            Fixture f; f.admit = false;
            rejects(ErrorCode::conflict, [&] { f.service.start(browser, f.request()); });
            require(f.starts == 1);
            f.throw_start = true;
            bool unknown = false;
            try { f.service.start(browser, f.request()); } catch (const std::runtime_error&) { unknown = true; }
            require(unknown && f.starts == 2);
        });
        std::cout << passed << " VM lifecycle checks passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
