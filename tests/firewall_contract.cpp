// SPDX-License-Identifier: GPL-3.0-or-later
#include "firewall_contract.h"
#include "contracts.h"
#include "network/firewall.h"
#include "network/links.h"
#include "common/identity.h"
#include <fcntl.h>
#include <fstream>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/syscall.h>

namespace droidvm::test {
namespace {
using namespace droidvm::network;
std::string directory, executable, daemon;
struct Case {
    std::string path = directory + "/fw-" + random_id(false);
    Fd fd;
    Iptables iptables;
    Case() { check(mkdir(path.c_str(), 0700) == 0, "create firewall case"); fd = Fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)); }
    void finish() {
        OwnedFirewall owner(fd.get(), getuid(), iptables);
        check(owner.recover_all().empty() && owner.inventory()["rules"].empty(), "firewall case ownership cleanup");
        for (const char* name : {"network-firewall.json", "network-firewall.json.bak", "network-firewall.json.corrupt", "fixture.apk", "droidvmd.lock"})
            unlinkat(fd.get(), name, 0);
        check(rmdir(path.c_str()) == 0, "firewall case empty");
    }
};
FirewallRule rule(bool ipv6 = false) {
    FirewallRule result; result.ipv6 = ipv6; result.input = "lo";
    result.source = ipv6 ? "fd91:fe21:44::1/64" : "198.18.231.1/24";
    result.protocol = "udp"; result.port_first = 20000; result.port_last = 20003;
    return result;
}
std::string tag(const OwnedFirewall& owner, const std::string& key = "test") {
    const auto inventory = owner.inventory();
    for (const auto& row : inventory["rules"]) if (row["key"] == key) return row["tag"].asString();
    throw std::runtime_error("missing firewall test identity");
}
void write_file(const std::string& path, const std::string& text) {
    Fd fd(open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    check(fd.get() >= 0 && write(fd.get(), text.data(), text.size()) == static_cast<ssize_t>(text.size()), "write firewall fixture");
}
void typed_rules_and_real_tables() {
    Case test;
    OwnedFirewall owned(test.fd.get(), getuid(), test.iptables);
    auto bad = rule(); bad.table = "filter; touch /invalid";
    error(ErrorCode::invalid_argument, [&] { owned.put("test", "invalid", bad); });
    bad = rule(); bad.input = "lo --flush";
    error(ErrorCode::invalid_argument, [&] { owned.put("test", "invalid", bad); });
    bad = rule(); bad.protocol = "--modprobe";
    error(ErrorCode::invalid_argument, [&] { owned.put("test", "invalid", bad); });
    bad = rule(); bad.input.clear(); bad.source.clear();
    error(ErrorCode::invalid_argument, [&] { owned.put("test", "invalid", bad); });
    check(owned.inventory()["rules"].empty(), "invalid rules rejected before intent persistence");
    for (const bool ipv6 : {false, true}) {
        auto desired = rule(ipv6);
        owned.put("test", "test", desired);
        const auto identity = tag(owned);
        check(test.iptables.tagged(desired, identity) == 1 && test.iptables.contains(desired, identity), "real family rule present by comment and full spec");
        owned.put("test", "test", desired);
        OwnedFirewall reloaded(test.fd.get(), getuid(), test.iptables);
        reloaded.put("test", "test", desired);
        check(test.iptables.tagged(desired, identity) == 1, "reload and repeated install do not duplicate rules");
        test.iptables.erase(desired, identity); reloaded.put("test", "test", desired);
        check(test.iptables.contains(desired, identity), "externally removed rule is repaired with persisted identity");
        auto changed = desired; changed.target = "DROP";
        error(ErrorCode::conflict, [&] { reloaded.put("test", "test", changed); });
        reloaded.remove("test", "test"); check(!test.iptables.tagged(desired, identity), "exact removal reclaims only registered rule");
        // Continue with one authoritative owner after reopening the inventory.
        owned.remove("test", "test");
    }
    ChildOptions capability; capability.argv = {"/system/bin/ip6tables", "-t", "nat", "-S"};
    const auto nat6 = Child(capability).communicate({}, 3s);
    check(!nat6.timed_out && (nat6.exit_code == 0 || nat6.error.find("Table does not exist") != std::string::npos), "classify IPv6 NAT availability");
    for (const bool ipv6 : {false, true}) for (const auto* target : {"MASQUERADE", "DNAT"}) {
        FirewallRule nat; nat.ipv6 = ipv6; nat.table = "nat"; nat.target = target;
        nat.source = ipv6 ? "fd91:fe21:45::/64" : "198.18.232.0/24";
        nat.chain = nat.target == "DNAT" ? "PREROUTING" : "POSTROUTING";
        if (nat.target == "DNAT") {
            nat.protocol = "tcp"; nat.port_first = 23000; nat.port_last = 23003;
            nat.translated_address = ipv6 ? "fd91:fe21:46::2" : "198.18.233.2";
            nat.translated_first = 24000; nat.translated_last = 24003;
        } else { nat.output = "lo"; nat.negate_output = true; }
        if (ipv6 && nat6.exit_code != 0) {
            error(ErrorCode::io_error, [&] { owned.put("test", "nat", nat); });
            check(owned.inventory()["rules"].empty(), "unsupported IPv6 NAT fails before allocating an ownership intent");
            std::cerr << "IPv6 NAT table unavailable in test namespace: explicit failure verified, no IPv6 NAT pass claimed" << std::endl;
            continue;
        }
        owned.put("test", "nat", nat); check(test.iptables.contains(nat, tag(owned, "nat")), "real typed NAT rule round trip");
        owned.remove("test", "nat");
    }
    test.finish();
}
void foreign_rules_and_ambiguity() {
    Case test; OwnedFirewall owned(test.fd.get(), getuid(), test.iptables);
    auto desired = rule();
    ChildOptions foreign;
    foreign.argv = {"/system/bin/iptables", "-A", "FORWARD", "-i", "lo", "-m", "comment", "--comment", "external \\\"quoted\\\" --comment data", "-j", "RETURN"};
    check(Child(foreign).communicate().exit_code == 0, "create unrelated rule with escaped comment");
    owned.put("test", "test", desired); auto identity = tag(owned);
    test.iptables.insert(desired, identity);
    check(owned.cleanup("test").size() == 1 && test.iptables.tagged(desired, identity) == 2, "ambiguous duplicates retained for explicit resolution");
    test.iptables.erase(desired, identity); owned.remove("test", "test");
    owned.put("test", "test", desired); identity = tag(owned);
    test.iptables.erase(desired, identity);
    auto replacement = desired; replacement.chain = "INPUT"; replacement.target = "DROP";
    test.iptables.insert(replacement, identity);
    owned.put("independent", "other", rule(true));
    check(owned.recover_all().size() == 1 && owned.inventory()["rules"].size() == 1 && test.iptables.contains(replacement, identity),
        "moved/replaced rule retained while independent family cleanup continues");
    test.iptables.erase(replacement, identity); check(owned.recover_all().empty(), "missing original rule retires safely");
    foreign.argv[1] = "-C";
    check(Child(foreign).communicate().exit_code == 0, "unrelated quoted rule preserved");
    foreign.argv[1] = "-D"; check(Child(foreign).communicate().exit_code == 0, "remove only test-owned foreign fixture");
    test.finish();
}
void races_and_write_failures() {
    Case test; bool duplicate = true;
    const auto desired = rule();
    OwnedFirewall owner(test.fd.get(), getuid(), test.iptables, [&](const char* stage) {
        if (duplicate && std::string_view(stage) == "firewall_rule_created") {
            const auto row = config::JsonFile(test.fd.get(), "network-firewall.json", getuid()).load()->value["rules"][0];
            test.iptables.insert(desired, row["tag"].asString());
        }
    });
    error(ErrorCode::conflict, [&] { owner.put("test", "test", desired); });
    auto identity = tag(owner);
    check(owner.cleanup("test").size() == 1, "creation race remains ambiguous rather than deleting arbitrary duplicates");
    duplicate = false; test.iptables.erase(desired, identity); owner.remove("test", "test");
    bool fail = true;
    OwnedFirewall uncertain(test.fd.get(), getuid(), test.iptables, {}, [&](const char* stage) {
        if (fail && std::string_view(stage) == "installed") throw std::runtime_error("injected firewall fsync failure");
    });
    bool rejected = false;
    try { uncertain.put("test", "test", desired); } catch (const config::CommitError&) { rejected = true; }
    check(rejected && uncertain.inventory()["rules"].size() == 1, "installed intent retained after uncertain durability failure");
    fail = false; uncertain.put("test", "test", desired);
    identity = tag(uncertain);
    auto replaced = desired; replaced.target = "DROP";
    bool race = true;
    OwnedFirewall removing(test.fd.get(), getuid(), test.iptables, [&](const char* stage) {
        if (race && std::string_view(stage) == "before_firewall_delete") {
            test.iptables.erase(desired, identity); test.iptables.insert(replaced, identity);
        }
    });
    check(removing.cleanup("test").size() == 1 && test.iptables.contains(replaced, identity), "delete race never removes changed foreign spec");
    race = false; test.iptables.erase(replaced, identity); check(removing.cleanup("test").empty(), "cleanup retry after conflict resolution");
    test.finish();
}
void inventory_scope_and_corruption() {
    Case test; const auto desired = rule();
    {
        OwnedFirewall owned(test.fd.get(), getuid(), test.iptables); owned.put("test", "test", desired);
        auto changed = owned.inventory(); changed["rules"][0]["scope"]["namespace_inode"] = Json::UInt64(1);
        config::JsonFile(test.fd.get(), "network-firewall.json", getuid()).save(changed);
        OwnedFirewall wrong(test.fd.get(), getuid(), test.iptables);
        check(wrong.recover_all().size() == 1 && test.iptables.contains(desired, tag(owned)), "same-boot wrong namespace never mutated");
        changed = owned.inventory(); changed["rules"][0]["scope"]["boot"] = random_id(true);
        config::JsonFile(test.fd.get(), "network-firewall.json", getuid()).save(changed);
        Iptables absent("/missing/iptables", "/missing/ip6tables");
        OwnedFirewall old_boot(test.fd.get(), getuid(), absent);
        check(old_boot.recover_all().empty() && test.iptables.contains(desired, tag(owned)),
            "old-boot records retire without executing tools or touching current kernel rules");
        config::JsonFile(test.fd.get(), "network-firewall.json", getuid()).save(owned.inventory());
        owned.remove("test", "test");
    }
    write_file(test.path + "/network-firewall.json", "{broken");
    error(ErrorCode::io_error, [&] { OwnedFirewall bad(test.fd.get(), getuid(), test.iptables); });
    // Recovering from the old backup could resurrect ownership of already
    // removed rules. Deliberately repair this test's known-empty latest state.
    Json::Value empty; empty["schema"] = 1; empty["rules"] = Json::Value(Json::arrayValue);
    config::JsonFile(test.fd.get(), "network-firewall.json", getuid()).save(empty);
    test.finish();
}
void atomic_restore_and_order() {
    Iptables iptables;
    for (const bool ipv6 : {false, true}) {
        auto accept = rule(ipv6), drop = accept; drop.target = "DROP";
        Iptables::TaggedRule foreign{accept, "droidvm:" + random_id(false)}, first{drop, "droidvm:" + random_id(false)},
            second{accept, "droidvm:" + random_id(false)}, missing{drop, "droidvm:" + random_id(false)};
        iptables.insert(foreign.rule, foreign.tag);
        iptables.replace({}, {first, second});
        check(iptables.at_head({first, second}) && iptables.contains(foreign.rule, foreign.tag), "ordered transaction preserves foreign tail");
        error(ErrorCode::io_error, [&] { iptables.replace({first, missing}, {}); });
        check(iptables.at_head({first, second}) && iptables.contains(first.rule, first.tag), "failed complete-spec deletion rolls back earlier deletion");
        auto wrong_family = second; wrong_family.rule = rule(!ipv6);
        error(ErrorCode::invalid_argument, [&] { iptables.replace({first}, {wrong_family}); });
        check(iptables.at_head({first, second}), "cross-family request rejected without changing table");
        iptables.replace({first, second}, {second, first});
        check(iptables.at_head({second, first}), "atomic reorder changes head order");
        iptables.replace({first, second}, {});
        check(iptables.at_head({foreign}), "batch deletion restores foreign head");
        iptables.erase(foreign.rule, foreign.tag);
    }
}
std::vector<OwnedFirewall::Rule> policy(bool ipv6, bool allow) {
    auto accept = rule(ipv6), drop = accept; drop.target = "DROP";
    return allow ? std::vector<OwnedFirewall::Rule>{{"accept", accept}, {"drop", drop}} : std::vector<OwnedFirewall::Rule>{{"drop", drop}};
}
void durable_table_updates() {
    for (const bool ipv6 : {false, true}) {
        Case test; OwnedFirewall owned(test.fd.get(), getuid(), test.iptables);
        const auto other = rule(!ipv6);
        owned.put("other", "independent", other);
        owned.replace_table("test", ipv6, "filter", policy(ipv6, false));
        const auto before = owned.inventory();
        owned.replace_table("test", ipv6, "filter", policy(ipv6, false));
        check(owned.inventory() == before, "unchanged policy keeps durable identities and avoids rewriting");
        owned.replace_table("test", ipv6, "filter", policy(ipv6, true));
        const auto accept_tag = tag(owned, "accept"), drop_tag = tag(owned, "drop");
        const auto desired = policy(ipv6, true);
        check(test.iptables.at_head({{desired[0].rule, accept_tag}, {desired[1].rule, drop_tag}}), "durable update installs caller order");
        // Order drift and a missing member each require a fresh atomic revision.
        test.iptables.erase(desired[1].rule, drop_tag); test.iptables.insert(desired[1].rule, drop_tag);
        owned.replace_table("test", ipv6, "filter", desired);
        check(tag(owned, "drop") != drop_tag, "head order drift repairs with a new revision");
        test.iptables.erase(desired[0].rule, tag(owned, "accept"));
        owned.replace_table("test", ipv6, "filter", desired);
        check(test.iptables.contains(desired[0].rule, tag(owned, "accept")), "missing policy rule repaired");
        const auto identity = tag(owned, "drop"); test.iptables.insert(desired[1].rule, identity);
        const auto unchanged = owned.inventory();
        error(ErrorCode::conflict, [&] { owned.replace_table("test", ipv6, "filter", {}); });
        check(owned.inventory() == unchanged, "ambiguous rule stops whole update before writing intent");
        test.iptables.erase(desired[1].rule, identity);
        OwnedFirewall reload(test.fd.get(), getuid(), test.iptables);
        reload.replace_table("test", ipv6, "filter", {});
        check(reload.inventory()["rules"].size() == 1 && test.iptables.contains(other, tag(reload, "independent")), "empty revision removes owner slice only");
        check(reload.recover_all().empty(), "remaining independent owner cleanup");
        test.finish();
    }
}
void batch_failure_retry() {
    for (const auto* phase : {"firewall_batch_intent_saved", "firewall_batch_committed"}) {
        Case test; bool fail = false;
        OwnedFirewall owned(test.fd.get(), getuid(), test.iptables, [&](const char* stage) {
            if (fail && std::string_view(stage) == phase) throw std::runtime_error("injected batch failure");
        });
        owned.replace_table("test", false, "filter", policy(false, false));
        fail = true; bool rejected = false;
        try { owned.replace_table("test", false, "filter", policy(false, true)); } catch (const std::runtime_error&) { rejected = true; }
        check(rejected && owned.inventory()["rules"].size() == 3, "both generations retained across incomplete update");
        fail = false; owned.replace_table("test", false, "filter", policy(false, true));
        check(owned.inventory()["rules"].size() == 2, "retry converges and retires stale generation");
        test.finish();
    }
    {
        Case test; bool race = false;
        OwnedFirewall owned(test.fd.get(), getuid(), test.iptables, [&](const char* stage) {
            if (!race || std::string_view(stage) != "firewall_batch_intent_saved") return;
            const auto inventory = config::JsonFile(test.fd.get(), "network-firewall.json", getuid()).load()->value;
            for (const auto& row : inventory["rules"]) if (row["key"].asString().starts_with("retired:") && row["rule"]["target"] == "ACCEPT")
                test.iptables.erase(FirewallRule::from(row["rule"]), row["tag"].asString());
        });
        owned.replace_table("test", false, "filter", policy(false, true));
        const auto previous_drop = tag(owned, "drop"); race = true;
        error(ErrorCode::io_error, [&] { owned.replace_table("test", false, "filter", policy(false, false)); });
        check(test.iptables.contains(policy(false, false)[0].rule, previous_drop), "failed kernel transaction preserves remaining old guard");
        race = false; owned.replace_table("test", false, "filter", policy(false, false));
        check(owned.inventory()["rules"].size() == 1, "retry repairs a preflight-to-commit deletion race");
        test.finish();
    }
    for (const int failed_save : {1, 2}) {
        Case test; int saves = 0, fail_at = 0;
        OwnedFirewall owned(test.fd.get(), getuid(), test.iptables, {}, [&](const char* stage) {
            if (std::string_view(stage) == "installed" && ++saves == fail_at) throw std::runtime_error("injected batch durability failure");
        });
        owned.replace_table("test", false, "filter", policy(false, false));
        saves = 0; fail_at = failed_save; bool rejected = false;
        try { owned.replace_table("test", false, "filter", policy(false, true)); } catch (const config::CommitError&) { rejected = true; }
        check(rejected, "uncertain intent/final save propagates failure");
        const auto saved_before_retry = saves;
        fail_at = 0; owned.replace_table("test", false, "filter", policy(false, true));
        check(owned.inventory()["rules"].size() == 2 && saves > saved_before_retry, "installed write failure retries durability even if kernel and journal already match");
        test.finish();
    }
    {
        Case test; bool fail = false; int saves = 0;
        OwnedFirewall owned(test.fd.get(), getuid(), test.iptables, {}, [&](const char* stage) {
            if (std::string_view(stage) != "installed") return;
            ++saves; if (fail) throw std::runtime_error("injected final removal sync failure");
        });
        owned.put("test", "test", rule()); fail = true; bool rejected = false;
        try { owned.remove("test", "test"); } catch (const config::CommitError&) { rejected = true; }
        check(rejected && owned.inventory()["rules"].empty(), "uncertain removal retains installed empty inventory");
        const auto before = saves; fail = false; owned.remove("test", "test");
        check(saves > before, "idempotent removal retries unconfirmed durability");
        test.finish();
    }
}
void orphan_mutator_barrier() {
    Case test;
    const auto wrapper = test.path + "/restore", pidfile = test.path + "/restore.pid";
    check(symlink("/proc/self/exe", wrapper.c_str()) == 0, "native delayed restore fixture");
    Fd xtables(open((test.path + "/xtables.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600));
    check(xtables.get() >= 0 && flock(xtables.get(), LOCK_EX | LOCK_NB) == 0, "hold private xtables fixture lock");
    ChildOptions options; options.argv = {"/proc/self/exe", "--firewall-crash", test.path, "4", "inflight"};
    Child child(options);
    pid_t pid = 0;
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!pid && !child.poll_exit() && std::chrono::steady_clock::now() < deadline) {
        std::ifstream file(pidfile); file >> pid;
        if (!pid) std::this_thread::sleep_for(5ms);
    }
    check(pid > 0, "delayed restore process reached exec barrier");
    Fd process(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));
    check(process.get() >= 0, "hold exact delayed restore identity");
    // Cleanup this deliberately orphaned group even when an assertion fails.
    struct Guard { int fd; ~Guard() { syscall(SYS_pidfd_send_signal, fd, SIGKILL, nullptr, 0); } } guard{process.get()};
    auto blocked = [&](const char* message) {
        OwnedFirewall reloaded(test.fd.get(), getuid(), test.iptables);
        bool unavailable = false;
        try { reloaded.recover_all(); } catch (const ServiceError& error) { unavailable = error.code() == ErrorCode::unavailable; }
        check(unavailable, message);
    };
    blocked("live owner holds operation barrier");
    check(child.signal(SIGKILL) && child.communicate({}, 2s).exit_code == -SIGKILL, "kill owner while restore remains live");
    pollfd alive{process.get(), POLLIN, 0};
    check(poll(&alive, 1, 0) == 0, "orphaned mutator is still live after owner death");
    OwnedFirewall reload(test.fd.get(), getuid(), test.iptables);
    blocked("live orphan retains operation barrier");
    check(reload.inventory()["rules"].size() == 3, "live inherited lock prevents premature intent retirement");
    check(syscall(SYS_pidfd_send_signal, process.get(), SIGCONT, nullptr, 0) == 0, "release orphaned restore");
    // Also prove the real tool retains the barrier across exec, while it waits
    // on its own private xtables lock (never block Android's host lock).
    bool entered = false;
    const auto exec_deadline = std::chrono::steady_clock::now() + 1s;
    while (!entered && std::chrono::steady_clock::now() < exec_deadline) {
        std::ifstream command("/proc/" + std::to_string(pid) + "/cmdline"); std::string name; std::getline(command, name, '\0');
        entered = name == "/system/bin/iptables-restore";
        if (!entered) std::this_thread::sleep_for(5ms);
    }
    check(entered, "orphan entered actual restore executable");
    blocked("actual restore after exec retains operation barrier");
    xtables = Fd();
    pollfd exited{process.get(), POLLIN, 0};
    check(poll(&exited, 1, 3000) == 1, "orphaned restore finishes within budget");
    check(reload.recover_all().empty(), "recovery safely reclaims either committed generation after tool exit");
    unlink(wrapper.c_str()); unlink(pidfile.c_str()); unlink((test.path + "/xtables.lock").c_str()); test.finish();
}
void crash_boundaries() {
    for (const bool ipv6 : {false, true}) for (const char* stage : {"firewall_intent_saved", "firewall_rule_created", "firewall_identity_saved",
            "before_firewall_delete", "firewall_rule_deleted", "firewall_record_removed"}) {
        Case test;
        ChildOptions options; options.argv = {"/proc/self/exe", "--firewall-crash", test.path, ipv6 ? "6" : "4", stage};
        const auto output = Child(options).communicate({}, 10s);
        check(output.exit_code == -SIGKILL && !output.timed_out, "kill firewall child at durable boundary");
        OwnedFirewall reloaded(test.fd.get(), getuid(), test.iptables);
        const auto before = reloaded.inventory();
        check(reloaded.recover_all().empty(), "recover firewall journal after real SIGKILL");
        for (const auto& row : before["rules"]) check(!test.iptables.tagged(FirewallRule::from(row["rule"]), row["tag"].asString()), "crash cleanup removes exact tagged rule");
        test.finish();
    }
}
void batch_crash_boundaries() {
    for (const bool ipv6 : {false, true}) for (const auto* stage : {"firewall_batch_intent_saved", "firewall_batch_committed", "firewall_batch_identity_saved"}) {
        Case test;
        ChildOptions options; options.argv = {"/proc/self/exe", "--firewall-crash", test.path, ipv6 ? "6" : "4", stage};
        const auto result = Child(options).communicate({}, 10s);
        check(result.exit_code == -SIGKILL && !result.timed_out, "kill batch owner at durable boundary");
        OwnedFirewall recovered(test.fd.get(), getuid(), test.iptables);
        const auto inventory = recovered.inventory();
        check(recovered.recover_all().empty(), "recover both possible atomic generations");
        for (const auto& row : inventory["rules"]) check(!test.iptables.tagged(FirewallRule::from(row["rule"]), row["tag"].asString()), "no batch rule remains after crash recovery");
        test.finish();
    }
}
void actual_daemon_recovery() {
    Case test; const auto desired = rule();
    OwnedFirewall owner(test.fd.get(), getuid(), test.iptables); owner.put("test", "test", desired);
    const auto identity = tag(owner);
    test.iptables.erase(desired, identity); auto changed = desired; changed.target = "DROP"; test.iptables.insert(changed, identity);
    write_file(test.path + "/fixture.apk", "firewall recovery fixture");
    ChildOptions options; options.argv = {daemon, "--run-dir", test.path, "--apk", test.path + "/fixture.apk"};
    auto rejected = Child(options).communicate({}, 10s);
    check(rejected.exit_code == 1 && rejected.error.find("Network firewall recovery incomplete") != std::string::npos &&
        access((test.path + "/droidvmd-port.txt").c_str(), F_OK) < 0 && test.iptables.contains(changed, identity),
        "daemon refuses readiness on changed rule and preserves it");
    test.iptables.erase(changed, identity); test.iptables.insert(desired, identity);
    Child process(options);
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (access((test.path + "/droidvmd-port.txt").c_str(), F_OK) < 0 && !process.poll_exit() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(10ms);
    check(!process.poll_exit() && access((test.path + "/droidvmd-port.txt").c_str(), F_OK) == 0 && !test.iptables.tagged(desired, identity),
        "actual daemon recovers firewall before publishing readiness");
    check(process.signal(SIGTERM) && process.communicate({}, 3s).exit_code == 128 + SIGTERM, "recovered daemon exits normally");
    bool updating = false;
    OwnedFirewall pending(test.fd.get(), getuid(), test.iptables, [&](const char* stage) {
        if (updating && std::string_view(stage) == "firewall_batch_committed") throw std::runtime_error("leave batch intent for real daemon");
    });
    pending.replace_table("batch", false, "filter", policy(false, false)); updating = true;
    try { pending.replace_table("batch", false, "filter", policy(false, true)); } catch (const std::runtime_error&) {}
    check(pending.inventory()["rules"].size() == 3, "leave both generations in real daemon recovery fixture");
    Child batch_process(options);
    const auto batch_deadline = std::chrono::steady_clock::now() + 10s;
    while (access((test.path + "/droidvmd-port.txt").c_str(), F_OK) < 0 && !batch_process.poll_exit() && std::chrono::steady_clock::now() < batch_deadline)
        std::this_thread::sleep_for(10ms);
    check(!batch_process.poll_exit() && access((test.path + "/droidvmd-port.txt").c_str(), F_OK) == 0, "actual daemon accepts recovered batch inventory");
    for (const auto& row : pending.inventory()["rules"])
        check(!test.iptables.tagged(FirewallRule::from(row["rule"]), row["tag"].asString()), "actual daemon removes both atomic generations before readiness");
    check(batch_process.signal(SIGTERM) && batch_process.communicate({}, 3s).exit_code == 128 + SIGTERM, "batch recovered daemon exits normally");
    test.finish();
}
void packets() { firewall_packet_contract(executable, directory); }
}
void firewall_namespace_contract(const std::string& netbox, const std::string& work, const std::string& daemon) {
    const auto path = work + "/firewall";
    check(mkdir(path.c_str(), 0700) == 0, "create firewall namespace fixture");
    ChildOptions options; options.argv = {"/proc/self/exe", "--firewall-namespace", netbox, path, daemon};
    const auto result = Child(options).communicate({}, 60s);
    std::cerr << "isolated firewall contracts: " << result.output << result.error << std::endl;
    check(result.exit_code == 0 && !result.timed_out && wire::parse(result.output)["passed"] == true, "isolated firewall contracts pass");
    check(rmdir(path.c_str()) == 0, "firewall namespace fixture empty");
}
int firewall_namespace_child(const std::string& netbox, const std::string& work, const std::string& program, bool orphan_only) {
    const auto scope = network_scope();
    if (unshare(CLONE_NEWNET) != 0 || same_scope(scope, network_scope())) return 70;
    executable = netbox; directory = work; daemon = program;
    if (orphan_only) return run({{"orphan_mutator_inherited_barrier", orphan_mutator_barrier}});
    return run({{"typed_rules_and_real_dual_stack_tables", typed_rules_and_real_tables}, {"foreign_rules_and_ambiguity", foreign_rules_and_ambiguity},
        {"creation_deletion_races_and_write_failure", races_and_write_failures}, {"scope_and_corrupt_primary", inventory_scope_and_corruption},
        {"twelve_firewall_sigkill_boundaries", crash_boundaries}, {"actual_daemon_firewall_recovery", actual_daemon_recovery},
        {"real_filter_and_masquerade_packets", packets}, {"atomic_restore_order_and_rollback", atomic_restore_and_order},
        {"durable_table_updates_and_repair", durable_table_updates}, {"batch_failures_and_durability_retry", batch_failure_retry},
        {"six_batch_sigkill_boundaries", batch_crash_boundaries}, {"orphan_mutator_inherited_barrier", orphan_mutator_barrier}});
}
int firewall_crash_child(const std::string& work, bool ipv6, const std::string& phase) {
    Fd fd(open(work.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    Iptables iptables("/system/bin/iptables", "/system/bin/ip6tables", phase == "inflight" ? work + "/restore" : "/system/bin/iptables-restore");
    bool armed = false;
    OwnedFirewall owner(fd.get(), getuid(), iptables, [&](const char* stage) {
        if (phase == stage && (!phase.starts_with("firewall_batch_") || armed)) kill(getpid(), SIGKILL);
    });
    if (phase.starts_with("firewall_batch_") || phase == "inflight") {
        owner.put("test", "drop", policy(ipv6, false)[0].rule);
        armed = true; owner.replace_table("test", ipv6, "filter", policy(ipv6, true)); return 74;
    }
    owner.put("test", "test", rule(ipv6)); owner.remove("test", "test"); return 74;
}
int firewall_delayed_restore(const std::string& executable) {
    const auto work = executable.substr(0, executable.rfind('/'));
    write_file(work + "/restore.pid", std::to_string(getpid()));
    if (setenv("XTABLES_LOCKFILE", (work + "/xtables.lock").c_str(), 1) != 0) return 75;
    // A stopped process group becomes orphaned when its owner dies: Linux
    // sends SIGHUP + SIGCONT. Keep this deliberate fixture alive through HUP.
    signal(SIGHUP, SIG_IGN);
    raise(SIGSTOP);
    execl("/system/bin/iptables-restore", "/system/bin/iptables-restore", "--noflush", "-w", "2", nullptr);
    return 76;
}
}
